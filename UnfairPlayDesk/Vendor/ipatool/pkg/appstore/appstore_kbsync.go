package appstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/majd/ipatool/v2/internal/sap/assets"
	"github.com/majd/ipatool/v2/internal/sap/machine"
	"github.com/majd/ipatool/v2/pkg/http"
)

const entDownloadPath = "/WebObjects/DownloadDispatch.woa/wa/ent/download"

type kbsyncGenerator func(context.Context, []byte, uint64) ([]byte, error)

func defaultKBSyncGenerator(ctx context.Context, hardwareID []byte, dsid uint64) ([]byte, error) {
	bundle, err := assets.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("load SAP assets for kbsync: %w", err)
	}

	data, err := machine.GenerateKBSync(ctx, bundle, hardwareID, dsid)
	if err != nil {
		return nil, fmt.Errorf("generate kbsync: %w", err)
	}

	return data, nil
}

func (t *appstore) sendPreferredDownload(ctx context.Context, endpointURL string, acc Account, app App, guid, versionID string, platform Platform) (http.Result[downloadResult], Platform, error) {
	endpoint, err := newDownloadEndpoint(endpointURL, entDownloadPath)
	if err != nil {
		return http.Result[downloadResult]{}, platform, err
	}

	if platform == "" {
		platform = PlatformIPhone
	}

	if versionID == "" && platform != PlatformIPhone && platform != PlatformIPad {
		reportDownloadStage(ctx, "正在查询目标平台版本")
		versionID, err = t.lookupLatestExternalVersionID(acc, app, platform)
		if err != nil {
			return http.Result[downloadResult]{}, platform, fmt.Errorf("failed to resolve platform version for ent/download: %w", err)
		}
	}

	res, err := t.sendEntDownload(ctx, endpoint, acc, app, guid, versionID)

	return res, platform, err
}

func (t *appstore) sendEntDownload(ctx context.Context, endpoint downloadProductEndpoint, acc Account, app App, guid, versionID string) (http.Result[downloadResult], error) {
	hardwareID, err := hex.DecodeString(guid)
	if err != nil || len(hardwareID) != 6 {
		return http.Result[downloadResult]{}, errors.New("ent/download requires a six-byte device GUID")
	}

	dsid, err := strconv.ParseUint(acc.DirectoryServicesID, 10, 64)
	if err != nil || dsid == 0 {
		return http.Result[downloadResult]{}, errors.New("ent/download requires a nonzero numeric account DSID")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Asset loading and guest execution also honor this deadline. Each guest
	// call retains the emulator's existing one-minute execution bound.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return http.Result[downloadResult]{}, fmt.Errorf("ent/download canceled: %w", err)
	}

	reportDownloadStage(ctx, "正在读取下载授权缓存")
	if cached := t.cachedKBSync(dsid, guid); cached != "" {
		proof, err := t.entDownloadProof(ctx, endpoint, guid, hardwareID)
		if err != nil {
			return http.Result[downloadResult]{}, err
		}

		res, err := t.sendEntDownloadRequest(ctx, endpoint, acc, app, guid, versionID, hardwareID, cached, proof)
		if err == nil {
			return res, nil
		}

		if ctx.Err() != nil {
			return res, fmt.Errorf("ent/download canceled: %w", ctx.Err())
		}

		// Retry a rejected cached blob once, bypassing the cache even if its
		// persistent entry could not be removed. Fresh blobs are never retried.
		t.invalidateKBSync(dsid, guid, cached)
	}

	proof, err := t.entDownloadProof(ctx, endpoint, guid, hardwareID)
	if err != nil {
		return http.Result[downloadResult]{}, err
	}

	reportDownloadStage(ctx, "正在准备下载授权")
	blob, err := t.generateKBSync(ctx, hardwareID, dsid)
	if err != nil {
		return http.Result[downloadResult]{}, err
	}

	res, err := t.sendEntDownloadRequest(ctx, endpoint, acc, app, guid, versionID, hardwareID, blob, proof)
	if err == nil && (res.Data.FailureType == "" || res.Data.FailureType == FailureTypeLicenseNotFound) {
		t.storeKBSync(dsid, guid, blob)
	}

	return res, err
}

func (t *appstore) entDownloadProof(ctx context.Context, endpoint downloadProductEndpoint, guid string, hardwareID []byte) (map[string]string, error) {
	reportDownloadStage(ctx, "正在生成商店验证信息")
	if t.authBackend == nil {
		return nil, nil
	}

	return t.storeAMDProof(ctx, fmt.Sprintf("%s?guid=%s", endpoint.baseURL, guid), hardwareID)
}

func (t *appstore) sendEntDownloadRequest(ctx context.Context, endpoint downloadProductEndpoint, acc Account, app App, guid, versionID string, hardwareID []byte, blob string, proof map[string]string) (http.Result[downloadResult], error) {
	serial := append([]byte{0x54, 0xc8, 0xb0, 0xa9, 0x88}, hardwareID[2:]...)
	request := t.downloadProductRequest(endpoint, acc, app, guid, "")

	// X-Token must not be forwarded to redirect destinations.
	request.NoRedirects = true
	request.Headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
	request.Headers["User-Agent"] = storeAuthenticationUserAgent
	request.Headers["X-Apple-Store-Front"] = acc.StoreFront
	request.Headers["X-Token"] = acc.PasswordToken

	for key, value := range proof {
		request.Headers[key] = value
	}

	request.Payload = &http.XMLPayload{Content: map[string]interface{}{
		"creditDisplay": "",
		"guid":          guid,
		"kbsync":        blob,
		"salableAdamId": strconv.FormatInt(app.ID, 10),
		"serialNumber":  base64.StdEncoding.EncodeToString(serial),
	}}

	if versionID != "" {
		request.Payload.(*http.XMLPayload).Content["externalVersionId"] = versionID
	}
	// The I/O deadline starts after local proof generation, not before it.
	requestContext, cancelRequest := context.WithTimeout(ctx, http.DefaultAuthenticationTimeout)
	defer cancelRequest()
	request.Context = requestContext
	reportDownloadStage(ctx, "正在向 Apple 请求下载地址")
	res, err := t.downloadClient.Send(request)
	if err != nil {
		return res, fmt.Errorf("send ent/download request: %w", err)
	}

	if res.Data.FailureType != "" {
		// A license or account failure is not a rejected kbsync blob.
		// Let Download handle it directly instead of regenerating or falling back.
		return res, nil
	}

	if err := validateDownloadResponse(res, app, versionID, "ent/download"); err != nil {
		return res, err
	}

	if res.Data.Items[0].URL == "" {
		return res, errors.New("ent/download response has no package URL")
	}

	return res, nil
}
