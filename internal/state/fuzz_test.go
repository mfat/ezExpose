package state

import (
	"os"
	"testing"
)

// FuzzLoadNeverTrustsADamagedRecord: whatever is in the file, Load either
// refuses it or returns a record this build understands.
func FuzzLoadNeverTrustsADamagedRecord(f *testing.F) {
	f.Add([]byte(`{"version":1,"install":"abc","exposures":[]}`))
	f.Add([]byte(`{"version":99,"install":"abc"}`))
	f.Add([]byte(`{"version":1,"install":`))
	f.Add([]byte(`{"version":1,"install":"a","exposures":[{"id":"x","resources":null}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s := Store{Dir: t.TempDir()}
		if err := os.WriteFile(s.file(), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := s.Load()
		if err != nil {
			return
		}
		if st.Version < 1 || st.Version > Version || st.Install == "" {
			t.Fatalf("accepted %+v", st)
		}
		for _, e := range st.Exposures {
			_ = e.URL()
			_ = st.Find(e.ID)
		}
	})
}
