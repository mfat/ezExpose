package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProc(t *testing.T) string {
	t.Helper()
	proc := t.TempDir()
	_ = os.MkdirAll(filepath.Join(proc, "net"), 0o755)
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1\n" + // 127.0.0.1:8080
		"   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1\n" + // 0.0.0.0:443
		"   2: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 333 1\n" // not listening
	tcp6 := "  sl  local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 444 1\n" + // [::]:22
		"   1: 00000000000000000000000001000000:20FB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 555 1\n" // [::1]:8443
	_ = os.WriteFile(filepath.Join(proc, "net", "tcp"), []byte(tcp), 0o644)
	_ = os.WriteFile(filepath.Join(proc, "net", "tcp6"), []byte(tcp6), 0o644)
	// Program 42 owns the socket on 8080; the rest belong to programs we can't see.
	_ = os.MkdirAll(filepath.Join(proc, "42", "fd"), 0o755)
	_ = os.WriteFile(filepath.Join(proc, "42", "comm"), []byte("jellyfin\n"), 0o644)
	_ = os.Symlink("socket:[111]", filepath.Join(proc, "42", "fd", "7"))
	_ = os.Symlink("/dev/null", filepath.Join(proc, "42", "fd", "0"))
	return proc
}

func TestListenersReadsTheKernelTables(t *testing.T) {
	found, hidden, err := Listeners(writeProc(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []Listener{
		{Address: "127.0.0.1", Port: 8080, Process: "jellyfin", PID: 42},
		{Address: "0.0.0.0", Port: 443},
		{Address: "::", Port: 22},
		{Address: "::1", Port: 8443},
	}
	if len(found) != len(want) || hidden != 3 {
		t.Fatalf("hidden %d, %+v", hidden, found)
	}
	for i := range want {
		if found[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, found[i], want[i])
		}
	}
	if !found[1].Everywhere() || found[1].Local() || !found[0].Local() || !found[2].Everywhere() || !found[3].Local() {
		t.Error("wrong scope")
	}
}

func TestListenersOnThisMachine(t *testing.T) {
	found, _, err := Listeners("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range found {
		if l.Port <= 0 || l.Address == "" {
			t.Fatalf("%+v", l)
		}
	}
}
