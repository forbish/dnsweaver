package axfr

import (
	"testing"

	"github.com/miekg/dns"
	"gitlab.bluewillows.net/root/dnsweaver/pkg/dnsupdate"
	"gitlab.bluewillows.net/root/dnsweaver/pkg/provider"
)

func TestConvertSRVPreservesRecordData(t *testing.T) {
	src := New()

	record, ok := src.convert("example.com", dnsupdate.Record{
		Name:     "_ldap._tcp.example.com.",
		Type:     dns.TypeSRV,
		TTL:      900,
		RData:    "dc1.example.com.",
		Priority: 0,
		Weight:   100,
		Port:     389,
	})
	if !ok {
		t.Fatal("convert returned ok=false")
	}
	if record.Type != provider.RecordTypeSRV {
		t.Fatalf("record.Type = %q, want %q", record.Type, provider.RecordTypeSRV)
	}
	if record.Target != "dc1.example.com." {
		t.Errorf("record.Target = %q, want %q", record.Target, "dc1.example.com.")
	}
	if record.SRV == nil {
		t.Fatal("record.SRV is nil")
	}
	if record.SRV.Priority != 0 {
		t.Errorf("record.SRV.Priority = %d, want 0", record.SRV.Priority)
	}
	if record.SRV.Weight != 100 {
		t.Errorf("record.SRV.Weight = %d, want 100", record.SRV.Weight)
	}
	if record.SRV.Port != 389 {
		t.Errorf("record.SRV.Port = %d, want 389", record.SRV.Port)
	}
}
