//go:build linux

package wan

import (
	"os"
	"strings"
	"testing"
)

type fakeRawConn struct {
	fd         uintptr
	called     bool
	controlErr error
}

func (f *fakeRawConn) Control(fn func(fd uintptr)) error {
	f.called = true
	if f.controlErr != nil {
		return f.controlErr
	}
	fn(f.fd)
	return nil
}
func (f *fakeRawConn) Read(fn func(fd uintptr) (done bool)) error  { return nil }
func (f *fakeRawConn) Write(fn func(fd uintptr) (done bool)) error { return nil }

func TestSharedWANDeviceBindingUsesSocketControl(t *testing.T) {
	// Use an actual regular file descriptor, never fd 0: stdin's kind is
	// environment-dependent. setsockopt on a file deterministically fails.
	f, err := os.CreateTemp(t.TempDir(), "not-a-socket")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw := &fakeRawConn{fd: f.Fd()}
	err = bindDeviceControl("not-a-real-wan")("udp4", "127.0.0.1:0", raw)
	if err == nil || !raw.called || !strings.Contains(err.Error(), "SO_BINDTODEVICE") {
		t.Fatalf("binding skipped socket control: called=%t, err=%v", raw.called, err)
	}
}
