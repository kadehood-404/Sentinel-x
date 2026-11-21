package scan

import "testing"

func TestShannonEntropy(t *testing.T) {
	if got := ShannonEntropy(""); got != 0 {
		t.Fatalf("empty entropy = %v, want 0", got)
	}
	if got := ShannonEntropy("aaaaaaaaaaaa"); got != 0 {
		t.Fatalf("constant entropy = %v, want 0", got)
	}
	if got := ShannonEntropy("a9f4c2e1b8d07365a9f4c2e1b8d07365"); got < 3.5 {
		t.Fatalf("hex entropy = %v, want >= 3.5", got)
	}
}

func TestScanDomainTunneling(t *testing.T) {
	if fs := ScanDomain("api.github.com"); len(fs) != 0 {
		t.Fatalf("normal domain should not trigger, got %+v", fs)
	}
	tunnel := "4a6f686e446f655365637265744b6579313233343536373839.exfil.evil.example"
	fs := ScanDomain(tunnel)
	if len(fs) == 0 {
		t.Fatalf("expected tunneling findings for %s", tunnel)
	}
	foundEncoded := false
	for _, f := range fs {
		if f.Kind != Anomaly {
			t.Errorf("expected Anomaly kind, got %s", f.Kind)
		}
		if f.Name == "dns_encoded_subdomain" || f.Name == "dns_long_label" {
			foundEncoded = true
		}
	}
	if !foundEncoded {
		t.Fatalf("expected encoded/long label finding, got %+v", fs)
	}
}
