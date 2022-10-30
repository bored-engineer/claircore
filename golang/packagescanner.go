// Package golang contains components for interrogating golang binaries in
// container layers.
package golang

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"fmt"
	"io/fs"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/tarfs"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for directories that seem like wheels or eggs, and looks at the
// metadata recorded there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "golang" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "0.0.1" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Scan attempts to find wheel or egg info directories and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "golang/Scanner.Scan",
		"version", ps.Version(),
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
	sys, err := tarfs.New(r)
	if err != nil {
		return nil, fmt.Errorf("golang: unable to open tar: %w", err)
	}

	exes, err := findExecutables(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("golang: failed to find executables: %w", err)
	}
	var ret []*claircore.Package
	for _, exe := range exes {
		// TODO: Avoid reading the entire file into memory via magic bytes check?
		b, err := fs.ReadFile(sys, exe)
		if err != nil {
			return nil, fmt.Errorf("fs.ReadFile of %q failed: %w", exe, err)
		}
		// Let the stdlib do the heavy lifting/parsing
		bi, err := buildinfo.Read(bytes.NewReader(b))
		if err != nil {
			// TODO: Check if something other than errUnrecognizedFormat and errNotGoExe
			continue
		}
		zlog.Debug(ctx).Str("file", exe).Str("pkg", bi.Main.Path).Str("go", bi.GoVersion).Msg("found go executable")
		// Add a package for the binary itself
		ret = append(ret, &claircore.Package{
			Name:           bi.Main.Path,
			Version:        bi.Main.Version,
			PackageDB:      "golang:" + exe,
			Kind:           claircore.BINARY,
			RepositoryHint: "Go",
		})
		// The stdlib "package" is based on the GoVersion
		ret = append(ret, &claircore.Package{
			Name:           "stdlib",
			Version:        bi.GoVersion,
			PackageDB:      "golang:" + exe,
			Kind:           claircore.BINARY,
			RepositoryHint: "Go",
		})
		// For each of the dependencies, add a package as well
		for _, dep := range bi.Deps {
			// TODO: What about module.Replace?
			ret = append(ret, &claircore.Package{
				Name:           dep.Path,
				Version:        dep.Version,
				PackageDB:      "golang:" + exe,
				Kind:           claircore.BINARY,
				RepositoryHint: "Go",
			})
		}
	}
	return ret, nil
}

// findExecutables finds executable files.
func findExecutables(ctx context.Context, sys fs.FS) (out []string, err error) {
	return out, fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.Type()&0111 != 0:
			zlog.Debug(ctx).Str("file", p).Msg("found executable")
		default:
			return nil
		}
		out = append(out, p)
		return nil
	})
}
