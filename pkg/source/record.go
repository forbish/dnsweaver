package source

import (
	"context"

	"gitlab.bluewillows.net/root/dnsweaver/pkg/provider"
)

// RecordSource discovers complete DNS records instead of hostnames.
type RecordSource interface {
	Name() string
	DiscoverRecords(ctx context.Context) ([]provider.Record, error)
}
