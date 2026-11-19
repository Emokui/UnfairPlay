package keychain

import (
	"bytes"
	"context"
	"io"
	"os"
	"syscall"
	"testing"
)

// Stand in for the GUI using a private socket, never the real login keychain.
func TestDesktopSessionMasterLifecycle(t *testing.T) {
	root := t.TempDir()
	legacy := newSessionTestKeychain()
	key := bytes.Repeat([]byte{0x67}, 32)
	open := func(command byte, reply []byte) Keychain {
		sockets, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		peer := os.NewFile(uintptr(sockets[0]), "gui")
		go func() {
			defer peer.Close()
			var op [1]byte
			if _, err := io.ReadFull(peer, op[:]); err != nil || op[0] != command {
				t.Errorf("expected request %c, got %q (%v)", command, op, err)
				return
			}
			if _, err := peer.Write(reply); err != nil {
				t.Error(err)
			}
		}()
		return NewDesktopSession(context.Background(), root, "profile-a", legacy, os.NewFile(uintptr(sockets[1]), "cli"))
	}
	if err := open('C', append([]byte{0}, key...)).Set("account", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if _, err := open('R', []byte{1, 'n', 'o'}).Get("account"); err == nil {
		t.Fatal("denied key read succeeded")
	}
	active := open('R', append([]byte{0}, key...))
	for i := 0; i < 2; i++ {
		data, err := active.Get("account")
		if err != nil || string(data) != "synthetic" {
			t.Fatalf("read: %q %v", data, err)
		}
	}
	if err := open('D', []byte{0}).(interface{ Revoke() error }).Revoke(); err != nil {
		t.Fatal(err)
	}
	if legacy.gets[sessionMasterKey] != 0 || legacy.sets[sessionMasterKey] != 0 {
		t.Fatal("CLI accessed master item directly")
	}
}
