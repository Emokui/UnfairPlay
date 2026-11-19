//nolint:nlreturn,wsl // Authentication steps are intentionally kept in protocol order.
package appstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/byteness/keyring"
	"github.com/majd/ipatool/v2/internal/sap/assets"
	"github.com/majd/ipatool/v2/internal/storeauth"
)

const (
	anisetteKeychainKey        = "anisette-v4"
	loginRuntimeTimeout        = 5 * time.Minute
	loginAuthenticationTimeout = 2 * time.Minute
)

func (t *appstore) nativeLogin(input LoginInput) (LoginOutput, error) {
	report := t.reportAuthenticationStage
	t.authStateMu.Lock()
	defer t.authStateMu.Unlock()

	if t.keychain == nil {
		return LoginOutput{}, errors.New("keychain is not configured")
	}
	if input.Password == "" {
		return LoginOutput{}, errors.New("password is required to sign in")
	}
	if len(t.anisetteState) == 0 {
		report("正在读取钥匙串中的设备认证状态，如有系统提示请授权")
		state, err := t.keychain.Get(anisetteKeychainKey)
		if err != nil && !errors.Is(err, keyring.ErrKeyNotFound) && !errors.Is(err, fs.ErrNotExist) {
			return LoginOutput{}, fmt.Errorf("read Apple authentication state: %w", err)
		}
		t.anisetteState = state
	}
	report("正在获取 Apple 认证配置")
	authCode, err := normalizeAuthCode(input.AuthCode)
	if err != nil {
		return LoginOutput{}, err
	}
	ctx := assets.WithProgress(input.Context, report)
	macAddress, err := t.machine.MacAddress()
	if err != nil {
		return LoginOutput{}, fmt.Errorf("get Store machine identity: %w", err)
	}
	guid, hardwareID, err := machineIdentity(macAddress)
	if err != nil {
		return LoginOutput{}, err
	}
	bag, err := t.bagContext(ctx, guid)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("get Store authentication bag: %w", err)
	}
	report("正在准备 Apple 认证组件")
	if _, err := assets.Load(ctx); err != nil {
		return LoginOutput{}, fmt.Errorf("prepare authentication components: %w", err)
	}
	headers, state, usedStoreAMD, err := t.prepareAuthentication(ctx, bag.AuthEndpoint, hardwareID)
	if err != nil {
		return LoginOutput{}, err
	}
	if usedStoreAMD {
		if err = t.keychain.Set(anisetteKeychainKey, state); err != nil {
			return LoginOutput{}, fmt.Errorf("save Apple authentication state: %w", err)
		}
	} else {
		identityState, err := storeauth.DeviceIdentityState(state)
		if err != nil {
			return LoginOutput{}, err
		}
		if err = t.keychain.Set(anisetteKeychainKey, identityState); err != nil {
			return LoginOutput{}, fmt.Errorf("save Apple authentication state: %w", err)
		}
	}
	t.anisetteState = state
	t.authenticationHeaders = headers.Clone()
	defer func() { t.authenticationHeaders = nil }()

	if t.actionSignerFactory == nil {
		return LoginOutput{}, errors.New("SAP action signer is not configured")
	}
	report("正在准备 Apple 认证签名")
	signerCtx, cancelSigner := context.WithTimeout(ctx, loginRuntimeTimeout)
	defer cancelSigner()
	signer, err := t.actionSignerFactory(signerCtx, bag.SAPConfig, hardwareID)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("failed to initialize SAP action signer: %w", err)
	}
	if signer == nil {
		return LoginOutput{}, errors.New("SAP action signer factory returned nil")
	}
	defer func() {
		if signer != nil {
			_ = signer.Close()
		}
	}()

	authenticate := func() (LoginOutput, error) {
		attempt, cancel := context.WithTimeout(ctx, loginAuthenticationTimeout)
		defer cancel()
		acc, err := t.loginContext(attempt, input.Email, input.Password, authCode, guid, bag.SAPConfig.AuthEndpoint, signer)
		if err != nil {
			return LoginOutput{}, err
		}
		return LoginOutput{Account: acc}, nil
	}

	output, authErr := t.authenticateWithProvisioning(authenticate, func(challenge string) error {
		report("正在完成 Apple Store 设备配置")
		provision, cancelProvision := context.WithTimeout(ctx, loginRuntimeTimeout)
		defer cancelProvision()
		kbsync, err := t.generateKBSync(provision, hardwareID, ^uint64(1))
		if err != nil {
			return fmt.Errorf("generate Apple Store provisioning kbsync: %w", err)
		}
		configured, err := storeauth.ProvisionStoreAnisette(provision, t.authHTTP, t.anisetteState, challenge, privateAppStoreProvisioningURL, storeAuthenticationUserAgent, kbsync, hardwareID)
		if err != nil {
			return fmt.Errorf("complete Apple Store provisioning: %w", err)
		}
		if err = t.keychain.Set(anisetteKeychainKey, configured); err != nil {
			return fmt.Errorf("save Apple authentication state: %w", err)
		}
		t.anisetteState = configured
		proof, nextState, err := storeauth.StoreAMDHeaders(provision, configured, bag.AuthEndpoint, hardwareID)
		if err != nil {
			return fmt.Errorf("prepare Store AMD proof: %w", err)
		}
		headers, err := storeauth.StoreAMDLoginHeaders(nextState, proof)
		if err != nil {
			return err
		}
		if err = t.keychain.Set(anisetteKeychainKey, nextState); err != nil {
			return fmt.Errorf("save Store AMD state: %w", err)
		}
		t.anisetteState = nextState
		t.authenticationHeaders = headers
		return nil
	})
	closeErr := signer.Close()
	signer = nil
	if closeErr != nil {
		closeErr = fmt.Errorf("failed to close SAP action signer: %w", closeErr)
	}
	if authErr != nil {
		if closeErr != nil {
			return LoginOutput{}, errors.Join(authErr, closeErr)
		}
		return LoginOutput{}, authErr
	}
	t.loginCompletedWithoutStoreAMD = !storeauth.HasStoreAMDState(t.anisetteState)
	if closeErr != nil {
		return output, closeErr
	}
	return output, nil
}

func (t *appstore) authenticateWithProvisioning(authenticate func() (LoginOutput, error), provision func(string) error) (LoginOutput, error) {
	output, challenge, err := t.storeProvisioningChallenge(authenticate)
	if err != nil || challenge == nil {
		return output, err
	}
	if err := provision(challenge.data); err != nil {
		return LoginOutput{}, err
	}
	output, challenge, err = t.storeProvisioningChallenge(authenticate)
	if challenge != nil {
		return output, fmt.Errorf("Apple requested Store provisioning again: %w", challenge)
	}
	return output, err
}

// Each proof may receive one RP retry with only the device identity.
func (t *appstore) storeProvisioningChallenge(authenticate func() (LoginOutput, error)) (LoginOutput, *authenticationMachineActionError, error) {
	output, err := authenticate()
	var action *authenticationMachineActionError
	if errors.As(err, &action) && action.action == "RP" {
		t.reportAuthenticationStage("正在响应 Apple 设备重新配置请求")
		for _, key := range []string{"X-Apple-AMD", "X-Apple-AMD-M", "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO"} {
			t.authenticationHeaders.Del(key)
		}
		output, err = authenticate()
	}
	if errors.As(err, &action) && action.action == "SP" {
		return output, action, nil
	}
	return output, nil, err
}

func (t *appstore) prepareAuthentication(ctx context.Context, endpoint string, hardwareID []byte) (http.Header, []byte, bool, error) {
	prepare, cancel := context.WithTimeout(ctx, loginRuntimeTimeout)
	defer cancel()
	if storeauth.HasStoreAMDState(t.anisetteState) {
		t.reportAuthenticationStage("正在复用本地设备认证状态")
		proof, state, err := storeauth.StoreAMDHeaders(prepare, t.anisetteState, endpoint, hardwareID)
		if err == nil {
			headers, err := storeauth.StoreAMDLoginHeaders(state, proof)
			return headers, state, true, err
		}
		if contextErr := prepare.Err(); contextErr != nil {
			return nil, nil, false, fmt.Errorf("prepare cached Store AMD proof: %w", contextErr)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, nil, false, fmt.Errorf("prepare cached Store AMD proof: %w", err)
		}
		if errors.Is(err, storeauth.ErrStoreAMDNotProvisioned) && len(state) != 0 {
			t.anisetteState = state
			if t.keychain != nil {
				if setErr := t.keychain.Set(anisetteKeychainKey, state); setErr != nil {
					return nil, nil, false, fmt.Errorf("save Apple authentication state: %w", setErr)
				}
			}
		}
	}

	t.reportAuthenticationStage("正在配置 Apple 设备认证")
	headers, state, err := storeauth.AnisetteHeaders(prepare, t.authHTTP, t.anisetteState)
	if err != nil {
		return nil, nil, false, fmt.Errorf("prepare Apple authentication: %w", err)
	}
	return headers, state, false, nil
}

func (t *appstore) reportAuthenticationStage(message string) {
	if t.authenticationProgress != nil {
		t.authenticationProgress(message)
	}
}
