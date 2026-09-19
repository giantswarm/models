package modelcar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"

	"github.com/giantswarm/models/internal/hub"
	"github.com/giantswarm/models/internal/spec"
)

// Files lists what the image of a specification holds, with hashes, without
// streaming the weights: an LFS file's hash is the Hub's record (a build fails
// unless the bytes match it, so an image that exists holds those bytes), and
// the small files the Hub keeps in git are read and hashed. The result is the
// list a build of the same revision produces, in the same order, so an image
// found already published gets the same SBOM as one built in the run.
func Files(ctx context.Context, m *spec.ModelImage, h *hub.Client) ([]FileDigest, error) {
	tree, err := h.Tree(ctx, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision)
	if err != nil {
		return nil, err
	}
	var files []hub.File
	for _, f := range tree {
		if !m.Excluded(f.Path) {
			files = append(files, f)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	out := make([]FileDigest, 0, len(files))
	for _, f := range files {
		d := FileDigest{Path: path.Join(spec.MountPath, f.Path), Size: f.Size, SHA256: f.SHA256}
		if d.SHA256 == "" {
			if d.SHA256, err = hashFile(ctx, h, m, f); err != nil {
				return nil, err
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func hashFile(ctx context.Context, h *hub.Client, m *spec.ModelImage, f hub.File) (string, error) {
	rc := h.Open(ctx, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision, f)
	defer func() { _ = rc.Close() }()
	sum := sha256.New()
	n, err := io.Copy(sum, rc)
	if err != nil {
		return "", fmt.Errorf("%s: %w", f.Path, err)
	}
	if n != f.Size {
		return "", fmt.Errorf("%s: read %d bytes, the tree lists %d", f.Path, n, f.Size)
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
