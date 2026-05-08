// Package axfr provides a RecordSource implementation that reads records from DNS
// zones via AXFR (RFC 5936 zone transfer).
//
// The source maps authoritative zone records to provider.Record entries so they can
// flow through the reconciler as source-provided records.
package axfr

import (
	"context"
	"log/slog"
	"net"
	"strings"

	"github.com/miekg/dns"
	"gitlab.bluewillows.net/root/dnsweaver/pkg/dnsupdate"
	"gitlab.bluewillows.net/root/dnsweaver/pkg/provider"
	"gitlab.bluewillows.net/root/dnsweaver/pkg/source"
)

const sourceName = "axfr"

// Config holds settings for AXFR source discovery.
type Config struct {
	Server               string
	Zones                []string
	Provider             string
	TSIGName             string
	TSIGKey              string
	TSIGAlgo             string
	SyncSOA              bool
	SyncNS               bool
	SyncApexAddress      bool
	AddressRewriteCIDRs  []string
	AddressRewriteTarget string
}

// Option configures an AXFR source.
type Option func(*AXFR)

// WithLogger sets the logger for the source.
func WithLogger(logger *slog.Logger) Option {
	return func(a *AXFR) {
		if logger != nil {
			a.logger = logger
		}
	}
}

// WithConfig sets the source configuration.
func WithConfig(cfg Config) Option {
	return func(a *AXFR) {
		a.config = cfg
		a.rewriteNets = parseRewriteCIDRs(cfg.AddressRewriteCIDRs, a.logger)
	}
}

// AXFR discovers DNS records from one or more authoritative zones using AXFR.
type AXFR struct {
	logger      *slog.Logger
	config      Config
	rewriteNets []*net.IPNet
}

// New creates a new AXFR source.
func New(opts ...Option) *AXFR {
	a := &AXFR{
		logger:      slog.Default(),
		config:      Config{},
		rewriteNets: nil,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Name returns the source identifier.
func (a *AXFR) Name() string {
	return sourceName
}

// DiscoverRecords performs an AXFR query for each configured zone and returns
// provider.Record values for discovered DNS records.
//
// SOA and NS records are filtered out unless SyncSOA / SyncNS are enabled.
// A/AAAA apex (zone-root) records are filtered out unless SyncApexAddress is enabled.
func (a *AXFR) DiscoverRecords(ctx context.Context) ([]provider.Record, error) {
	if strings.TrimSpace(a.config.Server) == "" {
		return nil, nil
	}
	if len(a.config.Zones) == 0 {
		return nil, nil
	}

	var all []provider.Record
	var lastErr error

	for _, zone := range a.config.Zones {
		zone = strings.TrimSpace(zone)
		if zone == "" {
			continue
		}

		client, err := a.newClient(zone)
		if err != nil {
			a.logger.Warn("failed to build AXFR client",
				slog.String("zone", zone),
				slog.String("error", err.Error()),
			)
			if lastErr == nil {
				lastErr = err
			}
			continue
		}

		records, err := client.ListByAXFR(ctx)
		if err != nil {
			a.logger.Warn("AXFR failed",
				slog.String("zone", zone),
				slog.String("server", a.config.Server),
				slog.String("error", err.Error()),
			)
			if lastErr == nil {
				lastErr = err
			}
			continue
		}

		for _, r := range records {
			record, ok := a.convert(zone, r)
			if !ok {
				continue
			}
			all = append(all, record)
		}
	}

	if len(all) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return all, nil
}

func (a *AXFR) newClient(zone string) (*dnsupdate.Client, error) {
	cfg := &dnsupdate.Config{
		Server:        a.config.Server,
		Zone:          normalizeZone(zone),
		TSIGKeyName:   a.config.TSIGName,
		TSIGSecret:    a.config.TSIGKey,
		TSIGAlgorithm: a.config.TSIGAlgo,
	}
	return dnsupdate.NewClient(cfg)
}

func (a *AXFR) convert(zone string, record dnsupdate.Record) (provider.Record, bool) {
	if !a.shouldInclude(zone, record) {
		return provider.Record{}, false
	}

	target := a.rewriteAddress(record.RData)

	recordType, ok := toProviderRecordType(record.Type)
	if !ok {
		a.logger.Debug("unsupported AXFR record type",
			slog.String("zone", zone),
			slog.String("type", record.TypeString()),
			slog.String("name", record.Name),
		)
		return provider.Record{}, false
	}

	metadata := map[string]string{
		"source": sourceName,
	}
	if a.config.Provider != "" {
		metadata["provider"] = a.config.Provider
	}

	return provider.Record{
		Hostname: strings.TrimSuffix(record.Name, "."),
		Type:     recordType,
		Target:   target,
		TTL:      int(record.TTL),
		Metadata: metadata,
	}, true
}

func (a *AXFR) shouldInclude(zone string, record dnsupdate.Record) bool {
	if record.Type == dns.TypeSOA && !a.config.SyncSOA {
		return false
	}
	if record.Type == dns.TypeNS && !a.config.SyncNS {
		return false
	}
	if !a.config.SyncApexAddress && (record.Type == dns.TypeA || record.Type == dns.TypeAAAA) && isApexRecord(zone, record.Name) {
		return false
	}

	return true
}

func (a *AXFR) rewriteAddress(target string) string {
	if strings.TrimSpace(a.config.AddressRewriteTarget) == "" || len(a.rewriteNets) == 0 {
		return target
	}
	if ip := net.ParseIP(strings.TrimSpace(target)); ip != nil {
		for _, network := range a.rewriteNets {
			if network.Contains(ip) {
				return a.config.AddressRewriteTarget
			}
		}
	}
	return target
}

func parseRewriteCIDRs(cidrs []string, logger *slog.Logger) []*net.IPNet {
	var networks []*net.IPNet
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			if logger != nil {
				logger.Warn("invalid AXFR address rewrite CIDR",
					slog.String("cidr", cidr),
				)
			}
			continue
		}
		networks = append(networks, network)
	}
	return networks
}

func normalizeZone(zone string) string {
	zone = strings.TrimSpace(zone)
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return zone
	}
	return zone + "."
}

func isApexRecord(zone, name string) bool {
	return strings.TrimSuffix(strings.ToLower(name), ".") == strings.TrimSuffix(strings.ToLower(zone), ".")
}

func toProviderRecordType(recordType uint16) (provider.RecordType, bool) {
	switch recordType {
	case dns.TypeA:
		return provider.RecordTypeA, true
	case dns.TypeAAAA:
		return provider.RecordTypeAAAA, true
	case dns.TypeCNAME:
		return provider.RecordTypeCNAME, true
	case dns.TypeTXT:
		return provider.RecordTypeTXT, true
	case dns.TypeSRV:
		return provider.RecordTypeSRV, true
	case dns.TypeHTTPS:
		return provider.RecordTypeHTTPS, true
	default:
		return "", false
	}
}

var _ source.RecordSource = (*AXFR)(nil)
