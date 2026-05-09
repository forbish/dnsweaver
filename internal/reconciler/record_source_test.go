package reconciler

import (
	"context"
	"testing"

	"gitlab.bluewillows.net/root/dnsweaver/pkg/provider"
	"gitlab.bluewillows.net/root/dnsweaver/pkg/source"
)

type staticRecordSource struct {
	name    string
	records []provider.Record
	err     error
}

func (s staticRecordSource) Name() string {
	return s.name
}

func (s staticRecordSource) DiscoverRecords(context.Context) ([]provider.Record, error) {
	return s.records, s.err
}

func TestDiscoverRecordHostnamesPreservesSRVHints(t *testing.T) {
	r := &Reconciler{
		logger: quietLogger(),
		recordSources: []source.RecordSource{
			staticRecordSource{
				name: "axfr",
				records: []provider.Record{
					{
						Hostname: "_ldap._tcp.example.com",
						Type:     provider.RecordTypeSRV,
						Target:   "dc1.example.com.",
						TTL:      900,
						SRV: &provider.SRVData{
							Priority: 0,
							Weight:   100,
							Port:     389,
						},
					},
				},
			},
		},
	}

	hostnames := r.discoverRecordHostnames(context.Background(), NewResult(false))
	hostname := findRecordSourceHostname(hostnames, "_ldap._tcp.example.com", "dc1.example.com.")
	if hostname == nil {
		t.Fatal("expected _ldap._tcp.example.com to be discovered")
	}
	if hostname.RecordHints == nil {
		t.Fatal("RecordHints is nil")
	}
	if hostname.RecordHints.SRV == nil {
		t.Fatal("RecordHints.SRV is nil")
	}
	if hostname.RecordHints.SRV.Priority != 0 {
		t.Errorf("RecordHints.SRV.Priority = %d, want 0", hostname.RecordHints.SRV.Priority)
	}
	if hostname.RecordHints.SRV.Weight != 100 {
		t.Errorf("RecordHints.SRV.Weight = %d, want 100", hostname.RecordHints.SRV.Weight)
	}
	if hostname.RecordHints.SRV.Port != 389 {
		t.Errorf("RecordHints.SRV.Port = %d, want 389", hostname.RecordHints.SRV.Port)
	}
}

func TestDiscoverRecordHostnamesKeepsMultipleSRVRecordsForSameOwner(t *testing.T) {
	r := &Reconciler{
		logger: quietLogger(),
		recordSources: []source.RecordSource{
			staticRecordSource{
				name: "axfr",
				records: []provider.Record{
					{
						Hostname: "_ldap._tcp.example.com",
						Type:     provider.RecordTypeSRV,
						Target:   "dc1.example.com.",
						TTL:      900,
						SRV: &provider.SRVData{
							Priority: 0,
							Weight:   100,
							Port:     389,
						},
					},
					{
						Hostname: "_ldap._tcp.example.com",
						Type:     provider.RecordTypeSRV,
						Target:   "dc2.example.com.",
						TTL:      900,
						SRV: &provider.SRVData{
							Priority: 0,
							Weight:   100,
							Port:     389,
						},
					},
				},
			},
		},
	}

	hostnames := r.discoverRecordHostnames(context.Background(), NewResult(false))
	if len(hostnames) != 2 {
		t.Fatalf("len(hostnames) = %d, want 2", len(hostnames))
	}
	if findRecordSourceHostname(hostnames, "_ldap._tcp.example.com", "dc1.example.com.") == nil {
		t.Fatal("expected dc1 SRV record to be discovered")
	}
	if findRecordSourceHostname(hostnames, "_ldap._tcp.example.com", "dc2.example.com.") == nil {
		t.Fatal("expected dc2 SRV record to be discovered")
	}
}

func TestReconcileCreatesMultipleSRVRecordsFromRecordSource(t *testing.T) {
	logger := quietLogger()
	mock := newTestMockProvider("test-dns")
	providers := provider.NewRegistry(logger)
	providers.RegisterFactory("mock", func(provider.FactoryConfig) (provider.Provider, error) {
		return mock, nil
	})
	if err := providers.CreateInstance(provider.ProviderInstanceConfig{
		Name:       "test-dns",
		TypeName:   "mock",
		RecordType: provider.RecordTypeA,
		Target:     "192.0.2.1",
		TTL:        300,
		Domains:    []string{"*"},
	}); err != nil {
		t.Fatalf("CreateInstance() error = %v", err)
	}

	cfg := DefaultConfig()
	cfg.CleanupOrphans = false
	cfg.OwnershipTracking = false
	r := New(nil, source.NewRegistry(logger), providers,
		WithConfig(cfg),
		WithLogger(logger),
		WithRecordSources(staticRecordSource{
			name: "axfr",
			records: []provider.Record{
				{
					Hostname: "_ldap._tcp.example.com",
					Type:     provider.RecordTypeSRV,
					Target:   "dc1.example.com.",
					TTL:      900,
					Metadata: map[string]string{"provider": "test-dns"},
					SRV:      &provider.SRVData{Priority: 0, Weight: 100, Port: 389},
				},
				{
					Hostname: "_ldap._tcp.example.com",
					Type:     provider.RecordTypeSRV,
					Target:   "dc2.example.com.",
					TTL:      900,
					Metadata: map[string]string{"provider": "test-dns"},
					SRV:      &provider.SRVData{Priority: 0, Weight: 100, Port: 389},
				},
			},
		}),
	)

	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.HostnamesDiscovered != 2 {
		t.Fatalf("HostnamesDiscovered = %d, want 2", result.HostnamesDiscovered)
	}

	created := mock.GetCreatedDNSRecords()
	if len(created) != 2 {
		t.Fatalf("created DNS records = %d, want 2: %+v", len(created), created)
	}
	assertCreatedSRVTarget(t, created, "dc1.example.com.")
	assertCreatedSRVTarget(t, created, "dc2.example.com.")
}

func TestEnsureRecordSRVDifferentTargetCreatesAdditionalRecord(t *testing.T) {
	logger := quietLogger()
	mock := newTestMockProvider("test-dns")
	mock.AddRecord(provider.Record{
		Hostname: "_ldap._tcp.example.com",
		Type:     provider.RecordTypeSRV,
		Target:   "dc1.example.com.",
		TTL:      900,
		SRV:      &provider.SRVData{Priority: 0, Weight: 100, Port: 389},
	})

	providers := provider.NewRegistry(logger)
	providers.RegisterFactory("mock", func(provider.FactoryConfig) (provider.Provider, error) {
		return mock, nil
	})
	if err := providers.CreateInstance(provider.ProviderInstanceConfig{
		Name:       "test-dns",
		TypeName:   "mock",
		RecordType: provider.RecordTypeA,
		Target:     "192.0.2.1",
		TTL:        300,
		Domains:    []string{"*"},
	}); err != nil {
		t.Fatalf("CreateInstance() error = %v", err)
	}

	r := &Reconciler{
		providers:      providers,
		config:         Config{Enabled: true, OwnershipTracking: false},
		logger:         logger,
		knownHostnames: make(map[string]struct{}),
	}
	r.syncAtomics()

	cache := newRecordCache(context.Background(), providers, logger)
	actions := r.ensureRecord(context.Background(), &source.Hostname{
		Name:   "_ldap._tcp.example.com",
		Source: "test",
		RecordHints: &source.RecordHints{
			Type:   "SRV",
			Target: "dc2.example.com.",
			TTL:    900,
			SRV:    &source.SRVHints{Priority: 0, Weight: 100, Port: 389},
		},
	}, cache)

	if len(actions) != 1 {
		t.Fatalf("len(actions) = %d, want 1", len(actions))
	}
	if actions[0].Type != ActionCreate || actions[0].Status != StatusSuccess {
		t.Fatalf("action = %#v, want successful create", actions[0])
	}
	if len(mock.GetDeleted()) != 0 {
		t.Fatalf("deleted records = %+v, want none", mock.GetDeleted())
	}

	created := mock.GetCreatedDNSRecords()
	if len(created) != 1 {
		t.Fatalf("created DNS records = %d, want 1: %+v", len(created), created)
	}
	assertCreatedSRVTarget(t, created, "dc2.example.com.")
}

func assertCreatedSRVTarget(t *testing.T, records []provider.Record, target string) {
	t.Helper()
	for _, record := range records {
		if record.Type == provider.RecordTypeSRV && record.Target == target {
			if record.SRV == nil {
				t.Fatalf("created SRV record for %s has nil SRV data", target)
			}
			return
		}
	}
	t.Fatalf("created SRV target %q not found in %+v", target, records)
}

func findRecordSourceHostname(hostnames map[string]*source.Hostname, name, target string) *source.Hostname {
	for _, hostname := range hostnames {
		if hostname == nil || hostname.Name != name || hostname.RecordHints == nil {
			continue
		}
		if hostname.RecordHints.Target == target {
			return hostname
		}
	}
	return nil
}
