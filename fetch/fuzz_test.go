package fetch

import (
	"strings"
	"testing"
)

func FuzzRangeStart(f *testing.F) {
	for _, h := range []string{"bytes 100-199/200", "bytes */200", "bytes -5-9/10", "bytes 99999999999999999999-1/2"} {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, header string) {
		start, ok := rangeStart(header)
		if ok && (start < 0 || !strings.HasPrefix(header, "bytes ")) {
			t.Fatalf("%q gave %d", header, start)
		}
	})
}
