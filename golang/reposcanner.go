// Package golang contains components for interrogating golang binaries in
// container layers.
package golang

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/tarfs"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)

	Repository = claircore.Repository{
		Name: "Go",
		URI:  "https://pkg.go.dev/",
	}
)

type RepoScanner struct{}

// Name implements scanner.VersionedScanner.
func (*RepoScanner) Name() string { return "golang" }

// Version implements scanner.VersionedScanner.
func (*RepoScanner) Version() string { return "0.0.1" }

// Kind implements scanner.VersionedScanner.
func (*RepoScanner) Kind() string { return "repository" }

// Scan attempts to find jar, war or ear and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (rs *RepoScanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Repository, error) {
	defer trace.StartRegion(ctx, "RepoScanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "golang/RepoScanner.Scan",
		"version", rs.Version(),
		"layer", layer.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	ra, ok := r.(io.ReaderAt)
	if !ok {
		err := errors.New("unable to coerce to io.ReaderAt")
		return nil, fmt.Errorf("opening layer failed: %w", err)
	}
	sys, err := tarfs.New(ra)
	if err != nil {
		return nil, err
	}

	exes, err := findExecutables(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("python: failed to find delicious egg: %w", err)
	}
	if len(exes) != 0 {
		// Just claim these came from golang.
		return []*claircore.Repository{&Repository}, nil
	}
	return nil, nil
}
