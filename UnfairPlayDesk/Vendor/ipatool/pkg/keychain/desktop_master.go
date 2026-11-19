package keychain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// The desktop app owns the keychain item. The socket serves a single request
// under the same session file lock used by standalone CLI clients.
func NewDesktopSession(ctx context.Context, directory, namespace string, legacy Keychain, channel *os.File) Keychain {
	return &session{ctx: ctx, directory: directory, namespace: namespace, legacy: legacy, desktop: channel}
}

func (s *session) desktopRequest(command byte) ([]byte, error) {
	if s.desktopErr != nil {
		return nil, s.desktopErr
	}
	data, err := exchangeMaster(s.desktop, command)
	s.desktopErr = err
	return data, err
}

func exchangeMaster(channel *os.File, command byte) ([]byte, error) {
	defer channel.Close()
	if _, err := channel.Write([]byte{command}); err != nil {
		return nil, fmt.Errorf("request desktop session key: %w", err)
	}
	var status [1]byte
	if _, err := io.ReadFull(channel, status[:]); err != nil {
		return nil, fmt.Errorf("read desktop session reply: %w", err)
	}
	if status[0] != 0 {
		message, err := io.ReadAll(io.LimitReader(channel, 1024))
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("desktop session key: %s", message)
	}
	if command == 'D' {
		return nil, nil
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(channel, key); err != nil {
		clear(key)
		return nil, errors.New("incomplete desktop session key")
	}
	return key, nil
}
