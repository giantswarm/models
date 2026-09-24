// Package modelcar builds and publishes a model image: a base image with a
// shell plus uncompressed tar layers holding a Hugging Face checkpoint under
// /models -- as few layers as DefaultMaxLayerSize allows, files whole, in path
// order -- and the specification's extra files in a layer of their own after
// them, as a two-platform index that both an amd64 and an arm64 node resolve
// to the same weights blobs.
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
	// URL is where an extra file was fetched from; empty for the checkpoint's files.
	URL string
}

// Source opens repository files.
type Source interface {
	Open(ctx context.Context, repository, revision string, f hub.File) io.ReadCloser
}

// Layer describes one layer to stream: checkpoint files, read from the
// repository at the revision, or extra files, each read from its URL.
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
// root with mode 0644 (0755 for directories) and the commit's timestamp. A
// file whose bytes hash to something other than the Hub's record (or, for an
// extra file, the specification's pin) fails the stream.
func (l *Layer) WriteTo(ctx context.Context, w io.Writer, src Source) error {
	return l.write(w, func(w io.Writer, f hub.File, name string) error {
		return l.copyFile(ctx, w, src, f, name)
	})
}

// Size is the byte count WriteTo produces, computed without reading a file:
// the headers are the same, and the tar writer passes a file's content through
// unchanged. Equal sizes of the same file list at the same revision mean
// equal layers, which is how a build recognises layers already published.
func (l *Layer) Size() (int64, error) {
	cw := &countingWriter{}
	zeros := make([]byte, 1<<20)
	err := l.write(cw, func(w io.Writer, f hub.File, _ string) error {
		for left := f.Size; left > 0; {
			n := min(left, int64(len(zeros)))
			if _, err := w.Write(zeros[:n]); err != nil {
				return err
			}
			left -= n
		}
		return nil
	})
	return cw.n, err
}

func (l *Layer) write(w io.Writer, content func(io.Writer, hub.File, string) error) error {
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
		if err := content(tw, f, name); err != nil {
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
		return fmt.Errorf("%s: wrote %d bytes, %d listed", f.Path, n, f.Size)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if f.SHA256 != "" && !strings.EqualFold(sum, f.SHA256) {
		pin := "the Hub records"
		if f.URL != "" {
			pin = "the specification pins"
		}
		return fmt.Errorf("%s: the bytes hash to sha256:%s, %s sha256:%s", f.Path, sum, pin, f.SHA256)
	}
	if l.Written != nil {
		l.Written(FileDigest{Path: name, Size: n, SHA256: sum, URL: f.URL})
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

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
