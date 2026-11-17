package appstore

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/majd/ipatool/v2/internal/sap/assets"
	apphttp "github.com/majd/ipatool/v2/pkg/http"
	"github.com/schollz/progressbar/v3"
	"howett.net/plist"
)

var (
	ErrLicenseRequired = errors.New("license is required")
)

type DownloadInput struct {
	CheckLicenseOnly   bool
	OmitUpdateMetadata bool
	OnStage            func(string)
	Context            context.Context
	Account            Account
	App                App
	OutputPath         string
	Progress           *progressbar.ProgressBar
	ExternalVersionID  string
	Platform           Platform
}

type DownloadOutput struct {
	SinfReplicated  bool
	DestinationPath string
	Sinfs           []Sinf
}

type downloadStageKey struct{}

func reportDownloadStage(ctx context.Context, message string) {
	if ctx == nil {
		return
	}
	if stage, ok := ctx.Value(downloadStageKey{}).(func(string)); ok {
		stage(message)
	}
}

func (t *appstore) Download(input DownloadInput) (DownloadOutput, error) {
	stage := input.OnStage
	if stage == nil {
		stage = func(string) {}
	}
	if input.Context == nil {
		input.Context = context.Background()
	}
	input.Context = assets.WithProgress(context.WithValue(input.Context, downloadStageKey{}, stage), stage)
	stage("\u6b63\u5728\u83b7\u53d6\u4e0b\u8f7d\u5730\u5740\u4e0e\u5e94\u7528\u8bb8\u53ef")
	macAddr, err := t.machine.MacAddress()
	if err != nil {
		return DownloadOutput{}, fmt.Errorf("failed to get mac address: %w", err)
	}

	guid := strings.ReplaceAll(strings.ToUpper(macAddr), ":", "")

	var machineGUID []byte
	if input.Platform == PlatformMacOS {
		guid, machineGUID, err = machineIdentity(macAddr)
		if err != nil {
			return DownloadOutput{}, fmt.Errorf("failed to resolve machine identity: %w", err)
		}
	}

	externalVersionID := input.ExternalVersionID
	if externalVersionID == "" && (input.Platform == PlatformAppleTV || input.Platform == PlatformWatchOS || input.Platform == PlatformVisionOS) {
		externalVersionID, err = t.lookupLatestExternalVersionID(input.Account, input.App, input.Platform)
		// Delisted tvOS apps may have no catalog offer but still be available
		// for redownload. Validate the returned package's platform below.
		missingTVOffer := input.Platform == PlatformAppleTV &&
			(errors.Is(err, errPlatformAppNotFound) || errors.Is(err, errPlatformOffersNotFound))
		if err != nil && !missingTVOffer {
			return DownloadOutput{}, fmt.Errorf("failed to resolve platform version: %w", err)
		}
	}

	if t.authBackend != nil {
		stage("正在准备 Apple 下载组件")
		if _, err := assets.Load(input.Context); err != nil {
			return DownloadOutput{}, fmt.Errorf("prepare download components: %w", err)
		}
	}
	ticketContext, cancelTicket := context.WithTimeout(input.Context, 2*time.Minute)
	res, resolvedPlatform, err := t.sendDownloadProduct(ticketContext, input.Account, input.App, guid, externalVersionID, input.Platform)
	cancelTicket()
	if err != nil {
		return DownloadOutput{}, err
	}

	if res.Data.FailureType == FailureTypePasswordTokenExpired ||
		res.Data.FailureType == FailureTypeSignInRequired ||
		res.Data.FailureType == FailureTypeDeviceVerificationFailed ||
		res.Data.FailureType == FailureTypeLicenseAlreadyExists {
		return DownloadOutput{}, ErrPasswordTokenExpired
	}

	if res.Data.FailureType == FailureTypeLicenseNotFound {
		return DownloadOutput{}, ErrLicenseRequired
	}

	if res.Data.CustomerMessage != "" && (res.Data.FailureType != "" || len(res.Data.Items) == 0) {
		return DownloadOutput{}, NewErrorWithMetadata(fmt.Errorf("received error: %s", res.Data.CustomerMessage), res)
	}

	if res.Data.FailureType != "" {
		return DownloadOutput{}, NewErrorWithMetadata(fmt.Errorf("received error: %s", res.Data.FailureType), res)
	}

	if len(res.Data.Items) == 0 {
		return DownloadOutput{}, NewErrorWithMetadata(errors.New("invalid response"), res)
	}

	if input.CheckLicenseOnly {
		return DownloadOutput{}, nil
	}

	item := res.Data.Items[0]

	version := "unknown"

	// Read the version from the item metadata
	if itemVersion, ok := item.Metadata["bundleShortVersionString"]; ok {
		version = fmt.Sprintf("%v", itemVersion)
	}

	packagePlatform, err := downloadPackagePlatform(input.Platform, item)
	if err != nil {
		return DownloadOutput{}, err
	}

	destination, err := t.resolveDestinationPath(input.App, version, input.OutputPath, packagePlatform)
	if err != nil {
		return DownloadOutput{}, fmt.Errorf("failed to resolve destination path: %w", err)
	}

	if packagePlatform == PlatformMacOS {
		return t.downloadMacPackage(input.Context, item, destination, machineGUID, input.Progress)
	}

	stage("正在下载 IPA")
	tmpPath := fmt.Sprintf("%s.tmp", destination)

	if err := t.downloadFile(input.Context, item.URL, tmpPath, input.Progress); err != nil {
		return DownloadOutput{}, fmt.Errorf("failed to download file: %w", err)
	}

	stage("正在检查下载包")
	if err := t.validatePackagePlatform(tmpPath, resolvedPlatform); err != nil {
		if removeErr := t.os.Remove(tmpPath); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to remove invalid package: %w", removeErr))
		}

		return DownloadOutput{}, fmt.Errorf("failed to validate package platform: %w", err)
	}

	stage("正在获取应用图标")
	artwork, err := t.downloadArtwork(input.Context, item.ArtworkURL)
	if err != nil {
		return DownloadOutput{}, fmt.Errorf("failed to download artwork: %w", err)
	}

	stage("正在整理 IPA 与应用许可")
	if err := t.applyPatches(item, input.Account, tmpPath, destination, artwork, input.OmitUpdateMetadata); err != nil {
		return DownloadOutput{}, fmt.Errorf("failed to apply patches: %w", err)
	}

	if err := t.os.Remove(tmpPath); err != nil {
		return DownloadOutput{}, fmt.Errorf("failed to remove file: %w", err)
	}

	stage("IPA 整理完成")
	return DownloadOutput{
		SinfReplicated:  true,
		DestinationPath: destination,
		Sinfs:           item.Sinfs,
	}, nil
}

type platformPackageInfo struct {
	SupportedPlatforms []string `plist:"CFBundleSupportedPlatforms,omitempty"`
}

func (*appstore) validatePackagePlatform(path string, platform Platform) error {
	var expectedPlatform string

	switch platform {
	case PlatformIPhone, PlatformIPad:
		expectedPlatform = "iPhoneOS"
	case PlatformAppleTV:
		expectedPlatform = "AppleTVOS"
	case PlatformWatchOS:
		expectedPlatform = "WatchOS"
	case PlatformVisionOS:
		expectedPlatform = "XROS"
	default:
		return nil
	}

	reader, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("failed to open zip reader: %w", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		if !isTopLevelAppInfoPlist(file.Name) {
			continue
		}

		infoFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open info plist: %w", err)
		}

		data, readErr := io.ReadAll(infoFile)
		closeErr := infoFile.Close()

		if readErr != nil {
			return fmt.Errorf("failed to read info plist: %w", readErr)
		}

		if closeErr != nil {
			return fmt.Errorf("failed to close info plist: %w", closeErr)
		}

		var info platformPackageInfo

		_, err = plist.Unmarshal(data, &info)
		if err != nil {
			return fmt.Errorf("failed to decode info plist: %w", err)
		}

		// Legacy iOS apps may predate CFBundleSupportedPlatforms. Only a
		// missing declaration qualifies; an empty or conflicting one does not.
		if expectedPlatform == "iPhoneOS" && info.SupportedPlatforms == nil {
			return nil
		}

		for _, supportedPlatform := range info.SupportedPlatforms {
			if supportedPlatform == expectedPlatform {
				return nil
			}
		}
	}

	return fmt.Errorf("downloaded package does not declare %s support", expectedPlatform)
}

func isTopLevelAppInfoPlist(path string) bool {
	parts := strings.Split(path, "/")

	return len(parts) == 3 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") && parts[2] == "Info.plist"
}

type downloadItemResult struct {
	PreflightPackageURL string                 `plist:"preflightPackageURL,omitempty"`
	ArtworkURL          string                 `plist:"artworkURL,omitempty"`
	HashMD5             string                 `plist:"md5,omitempty"`
	URL                 string                 `plist:"URL,omitempty"`
	Sinfs               []Sinf                 `plist:"sinfs,omitempty"`
	Metadata            map[string]interface{} `plist:"metadata,omitempty"`
}

type downloadResult struct {
	FailureType     string               `plist:"failureType,omitempty"`
	CustomerMessage string               `plist:"customerMessage,omitempty"`
	Items           []downloadItemResult `plist:"songList,omitempty"`
}

//nolint:nonamedreturns // Deferred close errors must propagate to callers.
func (t *appstore) downloadFile(ctx context.Context, src, dst string, progress *progressbar.ProgressBar) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for attempt := 0; ; attempt++ {
		err := t.downloadFileAttempt(ctx, src, dst, progress)
		if err == nil || attempt == 1 || ctx.Err() != nil {
			return err
		}
		var interrupted *downloadTransferError
		if !errors.As(err, &interrupted) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}
		reportDownloadStage(ctx, "下载连接中断，正在续传")
	}
}

type downloadTransferError struct{ error }

func (e *downloadTransferError) Unwrap() error { return e.error }

type downloadBodyReader struct{ io.Reader }

func (r downloadBodyReader) Read(buffer []byte) (int, error) {
	n, err := r.Reader.Read(buffer)
	if err != nil && err != io.EOF && !errors.Is(err, context.Canceled) {
		err = &downloadTransferError{err}
	}
	return n, err
}

func (t *appstore) downloadFileAttempt(ctx context.Context, src, dst string, progress *progressbar.ProgressBar) (err error) {
	req, err := t.httpClient.NewRequest("GET", src, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if req != nil {
		req = req.WithContext(ctx)
	}

	file, err := t.os.OpenFile(dst, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = joinCleanupError(err, "failed to close downloaded file", closeErr)
		}
	}()

	stat, err := t.os.Stat(dst)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	if req != nil && stat != nil {
		req.Header.Add("range", fmt.Sprintf("bytes=%d-", stat.Size()))
	}

	res, err := t.httpClient.Do(req)
	if err != nil {
		var network net.Error
		if errors.Is(err, apphttp.ErrTransferIdleTimeout) || errors.Is(err, io.EOF) ||
			errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
			(errors.As(err, &network) && network.Timeout()) {
			err = &downloadTransferError{err}
		}
		return fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()

	offset, remaining, total, complete, err := downloadResponseRange(res, stat.Size())
	if err != nil {
		return err
	}

	if complete {
		return nil
	}

	if res.StatusCode == gohttp.StatusOK {
		if err := file.Truncate(0); err != nil {
			return fmt.Errorf("failed to restart download: %w", err)
		}
	}

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("can not seek file: %w", err)
	}

	var writer io.Writer = file

	if progress != nil {
		progress.ChangeMax64(total)

		if err := progress.Set64(offset); err != nil {
			return fmt.Errorf("can not set bar progress: %w", err)
		}

		writer = io.MultiWriter(file, progress)
	}

	var body io.Reader = downloadBodyReader{res.Body}
	if remaining >= 0 {
		body = io.LimitReader(body, remaining)
	}

	written, err := io.Copy(writer, body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	if remaining >= 0 && written != remaining || total >= 0 && offset+written != total {
		return fmt.Errorf("download is incomplete: %w", io.ErrUnexpectedEOF)
	}

	return nil
}

func fileName(app App, version string) string {
	return packageFileName(app, version, "")
}

func packageFileName(app App, version string, platform Platform) string {
	var parts []string

	if app.BundleID != "" {
		parts = append(parts, app.BundleID)
	}

	if app.ID != 0 {
		parts = append(parts, strconv.FormatInt(app.ID, 10))
	}

	if version != "" {
		parts = append(parts, version)
	}

	extension := "ipa"
	if platform == PlatformMacOS {
		extension = "pkg"
	}

	return fmt.Sprintf("%s.%s", strings.Join(parts, "_"), extension)
}

func (t *appstore) resolveDestinationPath(app App, version string, path string, platform Platform) (string, error) {
	file := packageFileName(app, version, platform)

	if path == "" {
		workdir, err := t.os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current directory: %w", err)
		}

		return fmt.Sprintf("%s/%s", workdir, file), nil
	}

	isDir, err := t.isDirectory(path)
	if err != nil {
		return "", fmt.Errorf("failed to determine whether path is a directory: %w", err)
	}

	if isDir {
		return filepath.Join(path, file), nil
	}

	return path, nil
}

func (t *appstore) isDirectory(path string) (bool, error) {
	info, err := t.os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to read file metadata: %w", err)
	}

	if info == nil {
		return false, nil
	}

	return info.IsDir(), nil
}

//nolint:nonamedreturns // Deferred close errors must propagate to callers.
func (t *appstore) applyPatches(item downloadItemResult, acc Account, src, dst string, artwork []byte, omitUpdateMetadata bool) (err error) {
	srcZip, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("failed to open zip reader: %w", err)
	}
	defer srcZip.Close()

	dstFile, err := t.os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	defer func() {
		if closeErr := dstFile.Close(); closeErr != nil {
			err = joinCleanupError(err, "failed to close patched file", closeErr)
		}
	}()

	dstZip := zip.NewWriter(dstFile)
	defer func() {
		if closeErr := dstZip.Close(); closeErr != nil {
			err = joinCleanupError(err, "failed to close zip writer", closeErr)
		}
	}()

	replacing, err := t.sinfReplacementPaths(srcZip, item.Sinfs)
	if err != nil {
		return err
	}
	replacing["iTunesMetadata.plist"] = true
	if len(artwork) > 0 {
		replacing["iTunesArtwork"] = true
	}
	err = t.replicateZip(srcZip, dstZip, src, replacing)
	if err != nil {
		return fmt.Errorf("failed to replicate zip: %w", err)
	}

	if len(artwork) != 0 {
		file, err := dstZip.Create("iTunesArtwork")
		if err != nil {
			return fmt.Errorf("failed to create artwork: %w", err)
		}

		if _, err := file.Write(artwork); err != nil {
			return fmt.Errorf("failed to write artwork: %w", err)
		}
	}

	if err := t.appendSinfs(srcZip, dstZip, item.Sinfs); err != nil {
		return err
	}

	if !omitUpdateMetadata {
		if err := t.writeMetadata(item.Metadata, acc, dstZip); err != nil {
			return fmt.Errorf("failed to write metadata: %w", err)
		}
	}

	return nil
}

func (t *appstore) writeMetadata(metadata map[string]interface{}, acc Account, zip *zip.Writer) error {
	metadata["apple-id"] = acc.Email
	metadata["userName"] = acc.Email

	metadataFile, err := zip.Create("iTunesMetadata.plist")
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	data, err := plist.Marshal(metadata, plist.BinaryFormat)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	_, err = metadataFile.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}
