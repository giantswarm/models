package modelcar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/giantswarm/models/internal/hub"
	"github.com/giantswarm/models/internal/spec"
)

// Contents lists what the image of a specification holds: the checkpoint's
// files that are not excluded, in path order, and the extra files, in path
// order, each with the size its URL states, its pinned hash and its URL. An
// extra file that would land on a checkpoint file, or on a directory of one,
// is refused.
func Contents(ctx context.Context, m *spec.ModelImage, h *hub.Client) (checkpoint, extra []hub.File, err error) {
	tree, err := h.Tree(ctx, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision)
	if err != nil {
		return nil, nil, err
	}
	files, dirs := map[string]bool{}, map[string]bool{}
	for _, f := range tree {
		if m.Excluded(f.Path) {
			continue
		}
		checkpoint = append(checkpoint, f)
		files[f.Path] = true
		for dir := path.Dir(f.Path); dir != "."; dir = path.Dir(dir) {
			dirs[dir] = true
		}
	}
	sort.Slice(checkpoint, func(i, j int) bool { return checkpoint[i].Path < checkpoint[j].Path })
	for _, e := range m.Spec.ExtraFiles {
		if files[e.Path] || dirs[e.Path] {
			return nil, nil, fmt.Errorf("extra file %s: %s@%s has a file or directory at that path", e.Path, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision)
		}
		for dir := path.Dir(e.Path); dir != "."; dir = path.Dir(dir) {
			if files[dir] {
				return nil, nil, fmt.Errorf("extra file %s: %s@%s has a file at %s", e.Path, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision, dir)
			}
		}
		size, err := h.Stat(ctx, e.URL)
		if err != nil {
			return nil, nil, fmt.Errorf("extra file %s: %w", e.Path, err)
		}
		extra = append(extra, hub.File{Path: e.Path, Size: size, SHA256: e.SHA256, URL: e.URL})
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i].Path < extra[j].Path })
	return checkpoint, extra, nil
}

// VerifyExtraFiles streams every extra file and checks its bytes against the
// specification's pin, so a wrong hash fails the pull request that pins it
// rather than the publication after the merge.
func VerifyExtraFiles(ctx context.Context, h *hub.Client, m *spec.ModelImage, extra []hub.File) error {
	for _, f := range extra {
		sum, err := hashFile(ctx, h, m, f)
		if err != nil {
			return fmt.Errorf("extra file %w", err)
		}
		if !strings.EqualFold(sum, f.SHA256) {
			return fmt.Errorf("extra file %s: %s serves bytes that hash to sha256:%s, the specification pins sha256:%s", f.Path, f.URL, sum, f.SHA256)
		}
	}
	return nil
}

// Files lists what the image of a specification holds, with hashes, without
// streaming the weights: an LFS file's hash is the Hub's record and an extra
// file's the specification's pin (a build fails unless the bytes match, so an
// image that exists holds those bytes), and the small files the Hub keeps in
// git are read and hashed. The result is the list a build of the same
// specification produces, in the same order -- the checkpoint's files, then
// the extra files -- so an image found already published gets the same SBOM
// as one built in the run.
func Files(ctx context.Context, m *spec.ModelImage, h *hub.Client) ([]FileDigest, error) {
	checkpoint, extra, err := Contents(ctx, m, h)
	if err != nil {
		return nil, err
	}
	out, err := checkpointDigests(ctx, m, h, checkpoint)
	if err != nil {
		return nil, err
	}
	for _, f := range extra {
		out = append(out, FileDigest{Path: path.Join(spec.MountPath, f.Path), Size: f.Size, SHA256: f.SHA256, URL: f.URL})
	}
	return out, nil
}

// checkpointDigests is Files for the checkpoint's part of the image.
func checkpointDigests(ctx context.Context, m *spec.ModelImage, h *hub.Client, files []hub.File) ([]FileDigest, error) {
	out := make([]FileDigest, 0, len(files))
	for _, f := range files {
		d := FileDigest{Path: path.Join(spec.MountPath, f.Path), Size: f.Size, SHA256: f.SHA256}
		if d.SHA256 == "" {
			var err error
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
