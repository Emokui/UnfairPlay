package appstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/majd/ipatool/v2/internal/storeauth"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"go.uber.org/mock/gomock"
)

func TestStoreProvisioningWithCachedAMDHeaders(t *testing.T) {
	state := []byte(`{"Identifier":"AAECAwQFBgcICQoLDA0ODw=="}`)
	loginHeaders := func(proof string) http.Header {
		headers, err := storeauth.StoreAMDLoginHeaders(state, map[string]string{
			"X-Apple-AMD": proof, "X-Apple-AMD-M": proof + "-mid",
		})
		if err != nil {
			t.Fatal(err)
		}
		return headers
	}

	store := &appstore{authenticationHeaders: loginHeaders("old-proof")}
	calls, provisions := 0, 0
	out, err := store.authenticateWithProvisioning(func() (LoginOutput, error) {
		calls++
		request := store.loginRequest("test@example.invalid", "fixture", "", "001122334455", "https://example.invalid/", 1, nil)
		headers := make(http.Header)
		for key, value := range request.Headers {
			headers.Set(key, value)
		}
		if headers.Get("X-Mme-Device-Id") != "00010203-0405-0607-0809-0a0b0c0d0e0f" ||
			headers.Get("X-MMe-Client-Info") == "" || headers.Get("X-Apple-I-MD-LU") == "" ||
			headers.Get("X-Apple-I-Client-Time") == "" {
			t.Fatal("login request lost the persisted device identity")
		}
		wantProof := map[int]string{1: "old-proof", 3: "fresh-proof"}[calls]
		wantMID := ""
		if wantProof != "" {
			wantMID = wantProof + "-mid"
		}
		if headers.Get("X-Apple-AMD") != wantProof || headers.Get("X-Apple-AMD-M") != wantMID {
			t.Fatalf("attempt %d sent the wrong proof", calls)
		}

		switch calls {
		case 1, 3:
			return LoginOutput{}, &authenticationMachineActionError{action: "RP"}
		case 2:
			return LoginOutput{}, &authenticationMachineActionError{action: "SP", data: "synthetic-challenge"}
		case 4:
			return LoginOutput{Account: Account{Email: "test@example.invalid"}}, nil
		default:
			t.Fatal("unexpected extra authentication attempt")
			return LoginOutput{}, nil
		}
	}, func(challenge string) error {
		provisions++
		if challenge != "synthetic-challenge" {
			t.Fatalf("unexpected Store challenge: %q", challenge)
		}
		store.authenticationHeaders = loginHeaders("fresh-proof")
		return nil
	})
	if err != nil || out.Account.Email != "test@example.invalid" || calls != 4 || provisions != 1 {
		t.Fatalf("unexpected outcome: calls=%d, provisions=%d, error=%v", calls, provisions, err)
	}
}

func TestStoreProvisioningStopsAfterOneConfiguration(t *testing.T) {
	store := &appstore{}
	provisions := 0
	_, err := store.authenticateWithProvisioning(func() (LoginOutput, error) {
		return LoginOutput{}, &authenticationMachineActionError{action: "SP"}
	}, func(string) error {
		provisions++
		return nil
	})
	var action *authenticationMachineActionError
	if provisions != 1 || !errors.As(err, &action) || action.action != "SP" {
		t.Fatalf("unexpected repeated provisioning result: provisions=%d, error=%v", provisions, err)
	}
}

func TestStoreAMDProofReportsUnprovisionedStateForSessionRefresh(t *testing.T) {
	identityOnly, err := storeauth.DeviceIdentityState([]byte(`{"Identifier":"AAECAwQFBgcICQoLDA0ODw==","Provisioning":"bWFjaGluZQ==","RoutingInfo":123,"Kind":"machine"}`))
	if err != nil {
		t.Fatal(err)
	}

	store := &appstore{anisetteState: identityOnly}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = store.storeAMDProof(canceled, "https://downloaddispatch.itunes.apple.com/r/redownload?guid=001122334455", []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55})
	if !errors.Is(err, ErrStoreAMDNotProvisioned) || !IsSessionRefreshRequired(err) {
		t.Fatalf("expected ErrStoreAMDNotProvisioned triggering session refresh, got: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPrepareAuthenticationSkipsStoreAMDForMachineState(t *testing.T) {
	sentinel := errors.New("intercepted machine provisioning")
	store := &appstore{
		anisetteState: []byte(`{"Identifier":"AAECAwQFBgcICQoLDA0ODw==","Provisioning":"bWFjaGluZQ==","RoutingInfo":123,"Kind":"machine"}`),
		authHTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "gsa.apple.com" {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, sentinel
			}
			return nil, errors.New("unexpected host: " + r.URL.Host)
		})},
	}

	var stages []string
	store.authenticationProgress = func(msg string) { stages = append(stages, msg) }

	_, _, usedStoreAMD, err := store.prepareAuthentication(context.Background(), "https://auth.itunes.apple.com/auth/v1/native/fast", []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55})
	if !errors.Is(err, sentinel) || usedStoreAMD {
		t.Fatalf("expected direct AnisetteHeaders path hitting sentinel, got usedStoreAMD=%v err=%v", usedStoreAMD, err)
	}
	for _, stage := range stages {
		if stage == "正在复用本地设备认证状态" {
			t.Fatalf("must not attempt StoreAMDHeaders on machine-kind state; stages=%v", stages)
		}
	}
}

func TestAnisetteCommerceFallbackProofPreservesFullDeviceIdentity(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Apple-I-MD", "otp-token")
	headers.Set("X-Apple-I-MD-M", "mid-token")
	headers.Set("X-Apple-I-MD-RINFO", "17106176")
	headers.Set("X-Apple-I-MD-LU", "lu-hash")
	headers.Set("X-Mme-Device-Id", "00010203-0405-0607-0809-0a0b0c0d0e0f")
	headers.Set("X-MMe-Client-Info", "<MacBookPro13,3>")
	headers.Set("X-Apple-I-Client-Time", "2026-11-18T11:00:00Z")
	headers.Set("X-Apple-I-SRL-NO", "0")
	headers.Set("X-Apple-I-TimeZone", "UTC")
	headers.Set("X-Apple-Locale", "en_US")

	proof, ok := anisetteCommerceFallbackProof(headers)
	if !ok {
		t.Fatal("expected valid fallback proof")
	}
	if proof["X-Apple-AMD"] != "otp-token" || proof["X-Apple-AMD-M"] != "mid-token" {
		t.Fatalf("unexpected AMD mapping: %v", proof)
	}
	gotHeaders := make(http.Header, len(proof))
	for key, value := range proof {
		gotHeaders.Set(key, value)
	}
	if gotHeaders.Get("X-Apple-I-MD") != "" || gotHeaders.Get("X-Apple-I-MD-M") != "" {
		t.Fatalf("fallback proof leaked raw X-Apple-I-MD headers: %v", proof)
	}
	for _, required := range []string{
		"X-Apple-I-MD-RINFO",
		"X-Apple-I-MD-LU",
		"X-Mme-Device-Id",
		"X-MMe-Client-Info",
		"X-Apple-I-Client-Time",
		"X-Apple-I-SRL-NO",
		"X-Apple-I-TimeZone",
		"X-Apple-Locale",
	} {
		if gotHeaders.Get(required) != headers.Get(required) {
			t.Fatalf("missing or mismatched %s: got %q, want %q", required, gotHeaders.Get(required), headers.Get(required))
		}
	}

	headers.Del("X-Apple-I-MD")
	if _, ok := anisetteCommerceFallbackProof(headers); ok {
		t.Fatal("accepted fallback proof without X-Apple-I-MD")
	}
}

func TestNativeLoginRejectsEmptyPasswordBeforeKeychainAccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKeychain := keychain.NewMockKeychain(ctrl)
	store := &appstore{keychain: mockKeychain}
	_, err := store.nativeLogin(LoginInput{Context: context.Background(), Email: "user@example.invalid"})
	if err == nil || err.Error() != "password is required to sign in" {
		t.Fatalf("unexpected error for empty password: %v", err)
	}
}
