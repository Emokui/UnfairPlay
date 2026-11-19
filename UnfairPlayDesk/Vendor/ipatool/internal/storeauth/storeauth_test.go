package storeauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestStoreAuthentication(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Store Authentication")
}

var _ = Describe("local anisette state", func() {
	It("keeps TLS verification enabled for Apple authentication", func() {
		transport, ok := NewHTTPClient(nil).Transport.(*http.Transport)
		Expect(ok).To(BeTrue())
		Expect(transport.TLSClientConfig.InsecureSkipVerify).To(BeFalse())
		Expect(transport.TLSClientConfig.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
	})

	It("creates a fresh software identity", func() {
		state, err := decodeAnisetteState(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(state.Identifier).To(HaveLen(16))
		Expect(state.Provisioning).To(BeEmpty())
		Expect(state.RoutingInfo).To(BeZero())
	})

	It("rejects oversized persisted provisioning", func() {
		encoded, err := json.Marshal(anisetteState{Identifier: make([]byte, 16), Provisioning: make([]byte, anisetteLimit+1)})
		Expect(err).NotTo(HaveOccurred())
		_, err = decodeAnisetteState(encoded)
		Expect(err).To(MatchError("invalid persisted anisette state"))
	})

	It("builds the complete Apple header set", func() {
		state := &anisetteState{Identifier: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, RoutingInfo: 123}
		headers := anisetteHeaders(state, []byte("otp"), []byte("mid"))
		Expect(headers.Get("X-Apple-I-MD")).To(Equal("b3Rw"))
		Expect(headers.Get("X-Apple-I-MD-M")).To(Equal("bWlk"))
		Expect(headers.Get("X-Apple-I-MD-RINFO")).To(Equal("123"))
		Expect(headers.Get("X-Mme-Device-Id")).To(Equal("00010203-0405-0607-0809-0a0b0c0d0e0f"))
		Expect(headers.Get("X-MMe-Client-Info")).To(Equal(anisetteClientInfo))
	})

	It("distinguishes general machine Anisette state from Store AMD provisioning", func() {
		identifier := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		machineEncoded, err := json.Marshal(anisetteState{
			Identifier:   identifier,
			Provisioning: []byte("machine-adi-db"),
			RoutingInfo:  17106176,
			Kind:         stateKindMachine,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(HasStoreAMDState(nil)).To(BeFalse())
		Expect(HasStoreAMDState(machineEncoded)).To(BeFalse())

		identityOnly, err := DeviceIdentityState(machineEncoded)
		Expect(err).NotTo(HaveOccurred())
		Expect(HasStoreAMDState(identityOnly)).To(BeFalse())
		decodedIdentity, err := decodeAnisetteState(identityOnly)
		Expect(err).NotTo(HaveOccurred())
		Expect(decodedIdentity.Identifier).To(Equal(identifier))
		Expect(decodedIdentity.Provisioning).To(BeEmpty())
		Expect(decodedIdentity.RoutingInfo).To(BeZero())
		Expect(decodedIdentity.Kind).To(BeEmpty())

		storeEncoded, err := json.Marshal(anisetteState{
			Identifier:   identifier,
			Provisioning: []byte("store-adi-db"),
			Kind:         stateKindStore,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(HasStoreAMDState(storeEncoded)).To(BeTrue())

		legacyStoreEncoded, err := json.Marshal(anisetteState{
			Identifier:   identifier,
			Provisioning: []byte("legacy-store-adi-db"),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(HasStoreAMDState(legacyStoreEncoded)).To(BeTrue())

		invalidKind, err := json.Marshal(anisetteState{Identifier: identifier, Kind: "unknown"})
		Expect(err).NotTo(HaveOccurred())
		_, err = decodeAnisetteState(invalidKind)
		Expect(err).To(MatchError("invalid persisted anisette state"))

		// Canceled context guarantees StoreAMDHeaders fails fast before asset/VM open on unprovisioned states.
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		for _, unprovisioned := range [][]byte{nil, identityOnly, machineEncoded} {
			_, _, err := StoreAMDHeaders(canceled, unprovisioned, "https://downloaddispatch.itunes.apple.com/r/redownload?guid=001122334455", []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55})
			Expect(err).To(MatchError(ErrStoreAMDNotProvisioned))
		}
	})
})

func TestStoreProvisioningSendsOnlyDeviceIdentity(t *testing.T) {
	identifier := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Mme-Device-Id") != "00010203-0405-0607-0809-0a0b0c0d0e0f" ||
			r.Header.Get("X-Apple-I-MD-LU") == "" || r.Header.Get("X-MMe-Client-Info") == "" ||
			r.Header.Get("X-Apple-I-Client-Time") == "" {
			t.Error("SP request lost its device identity")
		}
		for _, key := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "X-Apple-AMD", "X-Apple-AMD-M"} {
			if r.Header.Get(key) != "" {
				t.Errorf("SP request unexpectedly sends %s", key)
			}
		}
		_, _ = w.Write([]byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>settingInfo</key><string>fixture</string><key>transportKey</key><string>fixture</string></dict></plist>`))
	}))
	defer server.Close()

	if _, _, _, err := finishStoreProvisioning(context.Background(), server.Client(), map[string]any{"clientData": "fixture"}, server.URL, "fixture", deviceIdentityHeaders(identifier)); err != nil {
		t.Fatal(err)
	}
}
