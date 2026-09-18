// Package modelcar builds and publishes a model image: a base image with a
// shell plus one uncompressed tar layer holding a Hugging Face checkpoint
// under /models, as a two-platform index that both an amd64 and an arm64
// node resolve to the same weights blob.
package modelcar

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/giantswarm/models/internal/hub"
)

// FileDigest is one file as written into the layer.
type FileDigest struct {
	// Path is the file's path inside the image, e.g. models/config.json.
	Path   string
	Size   int64
	SHA256 string
}

// Source opens repository files.
type Source interface {
	Open(ctx context.Context, repository, revision string, f hub.File) io.ReadCloser
}

// Layer describes the weights layer to stream.
type Layer struct {
	Repository string
	Revision   string
	Files      []hub.File
	// ModTime is every entry's timestamp: the checkpoint's commit time, so
	// the layer is the same bytes on every build of the revision.
	ModTime time.Time
	// Root is the directory the files go under ("models").
	Root string
	// Written is told about every file after its last byte, with the hash
	// computed from the bytes that went into the layer.
	Written func(FileDigest)
	// Read counts every byte read from the source as it arrives.
	Read func(n int)
}

// WriteTo streams the layer as an uncompressed tar: the root directory, then
// the files in path order with their parent directories, every entry owned by
// root with mode 0644 (0755 for directories) and the commit's timestamp. An
// LFS file whose bytes hash to something other than the Hub's record fails
// the stream.
func (l *Layer) WriteTo(ctx context.Context, w io.Writer, src Source) error {
	files := append([]hub.File(nil), l.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	tw := tar.NewWriter(w)
	dirs := map[string]bool{}
	mkdir := func(dir string) error {
		if dir == "." || dir == "" || dirs[dir] {
			return nil
		}
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir, Name: dir + "/", Mode: 0o755, ModTime: l.ModTime, Format: tar.FormatPAX,
		}); err != nil {
			return err
		}
		dirs[dir] = true
		return nil
	}
	if err := mkdir(l.Root); err != nil {
		return err
	}
	for _, f := range files {
		name := path.Join(l.Root, f.Path)
		for _, dir := range parents(name) {
			if err := mkdir(dir); err != nil {
				return err
			}
		}
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: name, Size: f.Size, Mode: 0o644, ModTime: l.ModTime, Format: tar.FormatPAX,
		}); err != nil {
			return err
		}
		if err := l.copyFile(ctx, tw, src, f, name); err != nil {
			return err
		}
	}
	return tw.Close()
}

func (l *Layer) copyFile(ctx context.Context, w io.Writer, src Source, f hub.File, name string) error {
	rc := src.Open(ctx, l.Repository, l.Revision, f)
	defer func() { _ = rc.Close() }()
	h := sha256.New()
	r := io.TeeReader(rc, h)
	if l.Read != nil {
		r = &countingReader{r: r, count: l.Read}
	}
	n, err := io.Copy(w, r)
	if err != nil {
		return fmt.Errorf("%s: %w", f.Path, err)
	}
	if n != f.Size {
		return fmt.Errorf("%s: wrote %d bytes, the tree lists %d", f.Path, n, f.Size)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if f.SHA256 != "" && !strings.EqualFold(sum, f.SHA256) {
		return fmt.Errorf("%s: the bytes hash to sha256:%s, the Hub records sha256:%s", f.Path, sum, f.SHA256)
	}
	if l.Written != nil {
		l.Written(FileDigest{Path: name, Size: n, SHA256: sum})
	}
	return nil
}

// parents lists the directories above a file path, outermost first, excluding
// the root itself.
func parents(name string) []string {
	var out []string
	for dir := path.Dir(name); dir != "." && dir != "/"; dir = path.Dir(dir) {
		out = append(out, dir)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

type countingReader struct {
	r     io.Reader
	count func(int)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.count(n)
	}
	return n, err
}
