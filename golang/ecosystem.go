package golang

import (
	"context"

	"github.com/quay/claircore/internal/indexer"
)

var scanners = []indexer.PackageScanner{&Scanner{}}
var reposcaners = []indexer.RepositoryScanner{&RepoScanner{}}

// NewEcosystem provides the set of scanners for the python ecosystem.
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners:      func(_ context.Context) ([]indexer.PackageScanner, error) { return scanners, nil },
		DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) { return nil, nil },
		RepositoryScanners:   func(_ context.Context) ([]indexer.RepositoryScanner, error) { return reposcaners, nil },
		Coalescer:            NewCoalescer,
	}
}
