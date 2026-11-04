package tailscale

import "testing"

func FuzzOlderIsAnOrder(f *testing.F) {
	f.Add("1.52.0", "1.104.4")
	f.Add("1.104.4-t9382131", "v1.104.4")
	f.Add("", "1..2")
	f.Fuzz(func(t *testing.T, a, b string) {
		if Older(a, b) && Older(b, a) {
			t.Fatalf("%q and %q are each older than the other", a, b)
		}
		if Older(a, a) {
			t.Fatalf("%q is older than itself", a)
		}
	})
}
