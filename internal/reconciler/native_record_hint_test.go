package reconciler

import (
	"context"
	"testing"

	"gitlab.bluewillows.net/root/dnsweaver/pkg/provider"
	"gitlab.bluewillows.net/root/dnsweaver/pkg/source"
)

func TestEnsureRecordProviderHintCreatesSiblingARecord(t *testing.T) {
	logger := quietLogger()
	mock := newTestMockProvider("compute-dns")
	mock.AddRecord(provider.Record{
		Hostname: "ns.example.com",
		Type:     provider.RecordTypeA,
		Target:   "10.0.0.2",
		TTL:      300,
	})
	mock.AddRecord(provider.OwnershipRecord("ns.example.com", 300, "dnsweaver-storage", nil))

	providers := provider.NewRegistry(logger)
	providers.SetInstanceID("dnsweaver-compute")
	providers.RegisterFactory("mock", func(provider.FactoryConfig) (provider.Provider, error) {
		return mock, nil
	})
	if err := providers.CreateInstance(provider.ProviderInstanceConfig{
		Name:       "compute-dns",
		TypeName:   "mock",
		RecordType: provider.RecordTypeA,
		Target:     "10.0.0.6",
		TTL:        300,
		Domains:    []string{"*.example.com"},
	}); err != nil {
		t.Fatalf("CreateInstance() error = %v", err)
	}

	r := &Reconciler{
		providers: providers,
		config: Config{
			Enabled:           true,
			OwnershipTracking: true,
			AdoptExisting:     false,
			InstanceID:        "dnsweaver-compute",
		},
		logger:         logger,
		knownHostnames: make(map[string]struct{}),
	}
	r.syncAtomics()

	cache := newRecordCache(context.Background(), providers, logger)
	actions := r.ensureRecord(context.Background(), &source.Hostname{
		Name:   "ns.example.com",
		Source: "dnsweaver",
		RecordHints: &source.RecordHints{
			Provider: "compute-dns",
		},
	}, cache)

	if len(actions) != 1 {
		t.Fatalf("len(actions) = %d, want 1", len(actions))
	}
	if actions[0].Type != ActionCreate || actions[0].Status != StatusSuccess {
		t.Fatalf("action = %#v, want successful create", actions[0])
	}
	if deleted := mock.GetDeleted(); len(deleted) != 0 {
		t.Fatalf("deleted records = %+v, want none", deleted)
	}

	created := mock.GetCreatedDNSRecords()
	if len(created) != 1 {
		t.Fatalf("created DNS records = %d, want 1: %+v", len(created), created)
	}
	if created[0].Type != provider.RecordTypeA || created[0].Target != "10.0.0.6" {
		t.Fatalf("created record = %+v, want A 10.0.0.6", created[0])
	}
}
