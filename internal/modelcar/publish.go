package modelcar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/giantswarm/models/internal/hub"
	"github.com/giantswarm/models/internal/registry"
	"github.com/giantswarm/models/internal/spec"
)

// Annotation keys on the index and labels on every image config.
const (
	AnnotationRepository = "io.giantswarm.models.huggingface.repository"
	AnnotationRevision   = "io.giantswarm.models.huggingface.revision"
	AnnotationFiles      = "io.giantswarm.models.files"
	AnnotationWeights    = "io.giantswarm.models.weights.bytes"
	AnnotationLayers     = "io.giantswarm.models.weights.layers"
	AnnotationBase       = "io.giantswarm.models.base"
)

// DefaultMaxLayerSize bounds one weights layer. A registry finalizes a blob in
// time proportional to its size -- Azure Container Registry's gateway gives up
// after eight minutes, which a 106 GB blob does not fit -- and a node pulls
// layers in parallel, so the checkpoint is cut into layers of at most this
// many bytes, files whole, in path order.
const DefaultMaxLayerSize = 8 << 30

// Platforms every image is published for. The weights layer is shared; only
// the base image's layer differs.
var Platforms = []v1.Platform{
	{OS: "linux", Architecture: "amd64"},
	{OS: "linux", Architecture: "arm64"},
}

// Options configure a publication.
type Options struct {
	// Registry is the repository prefix, e.g. gsoci.azurecr.io/giantswarm/models;
	// the image goes to <Registry>/<name>:<tag>.
	Registry name.Repository
	// Hub reads the checkpoint.
	Hub *hub.Client
	// Auth signs in to the registry.
	Auth authn.Authenticator
	// Source is the URL recorded as org.opencontainers.image.source.
	Source string
	// Tool names the builder in the image's history.
	Tool string
	// ChunkSize is the blob upload's PATCH size; the uploader's default when zero.
	ChunkSize int
	// MaxLayerSize bounds one weights layer; DefaultMaxLayerSize when zero.
	MaxLayerSize int64
	// ProgressInterval is how often the transfer is logged; 30 s when zero.
	ProgressInterval time.Duration
	// Log receives progress lines.
	Log func(format string, args ...any)
	// Transport carries the registry requests; http.DefaultTransport when nil.
	Transport http.RoundTripper
}

// Published is the result of publishing one specification.
type Published struct {
	// Reference is the tag the image is published under.
	Reference name.Tag
	// Digest is the index digest: what a policy verifies and a node pulls.
	Digest v1.Hash
	// Manifests are the per-platform image digests.
	Manifests map[string]v1.Hash
	// Layers are the weights layers' descriptors, in image order.
	Layers []v1.Descriptor
	// Files lists what went into the layer, with hashes.
	Files []FileDigest
	// Base is the base image reference with its digest.
	Base string
	// Created is the image's timestamp: the checkpoint's commit time.
	Created time.Time
	// Existed reports that the tag already held this checkpoint and nothing was
	// built or pushed.
	Existed bool
}

// Publish builds the image for a specification and pushes it, or finds it
// already there. The weights never touch local disk: each file streams from
// the Hub through the tar writer into the registry's blob upload.
func Publish(ctx context.Context, m *spec.ModelImage, o Options) (*Published, error) {
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.Transport == nil {
		o.Transport = http.DefaultTransport
	}
	if o.ProgressInterval <= 0 {
		o.ProgressInterval = 30 * time.Second
	}
	repo, err := name.NewRepository(o.Registry.String()+"/"+m.Metadata.Name, insecureIf(o.Registry))
	if err != nil {
		return nil, err
	}
	tag := repo.Tag(m.Tag())
	remoteOpts := []remote.Option{remote.WithContext(ctx), remote.WithAuth(o.Auth), remote.WithTransport(o.Transport), remote.WithUserAgent(o.Tool)}

	if existing, err := existing(m, tag, remoteOpts); err != nil {
		return nil, err
	} else if existing != nil {
		o.Log("%s already holds %s@%s; nothing to build", tag, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision)
		return existing, nil
	}

	rev, err := o.Hub.Revision(ctx, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision)
	if err != nil {
		return nil, err
	}
	all, err := o.Hub.Tree(ctx, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision)
	if err != nil {
		return nil, err
	}
	var files []hub.File
	var total int64
	for _, f := range all {
		if m.Excluded(f.Path) {
			continue
		}
		files = append(files, f)
		total += f.Size
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: every file of the checkpoint is excluded", m.Path)
	}

	bases, baseRef, err := baseImages(ctx, m.Base(), remoteOpts)
	if err != nil {
		return nil, err
	}

	o.Log("building %s from %s@%s: %d files, %s, base %s", tag, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision, len(files), humanBytes(total), baseRef)
	layers, digests, err := streamLayers(ctx, m, files, rev.LastModified, total, repo, o)
	if err != nil {
		return nil, err
	}
	var weights int64
	for _, l := range layers {
		weights += l.Size
	}

	labels := map[string]string{
		"org.opencontainers.image.title":       m.Metadata.Name,
		"org.opencontainers.image.description": m.Spec.Description,
		"org.opencontainers.image.source":      o.Source,
		"org.opencontainers.image.url":         m.HubURL(),
		"org.opencontainers.image.created":     rev.LastModified.Format(time.RFC3339),
		"org.opencontainers.image.version":     m.Spec.HuggingFace.Revision,
		"org.opencontainers.image.licenses":    m.Spec.License,
		AnnotationRepository:                   m.Spec.HuggingFace.Repository,
		AnnotationRevision:                     m.Spec.HuggingFace.Revision,
		AnnotationFiles:                        fmt.Sprint(len(files)),
		AnnotationWeights:                      fmt.Sprint(weights),
		AnnotationLayers:                       fmt.Sprint(len(layers)),
		AnnotationBase:                         baseRef,
	}
	for k, v := range labels {
		if v == "" {
			delete(labels, k)
		}
	}

	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	manifests := map[string]v1.Hash{}
	for _, b := range bases {
		img, err := appendWeights(b.image, layers, labels, rev.LastModified, o.Tool, m)
		if err != nil {
			return nil, err
		}
		d, err := img.Digest()
		if err != nil {
			return nil, err
		}
		manifests[b.platform.String()] = d
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &b.platform}})
	}
	idx = mutate.Annotations(idx, labels).(v1.ImageIndex)
	if err := remote.WriteIndex(tag, idx, remoteOpts...); err != nil {
		return nil, fmt.Errorf("pushing %s: %w", tag, err)
	}
	indexDigest, err := idx.Digest()
	if err != nil {
		return nil, err
	}
	o.Log("pushed %s@%s (%d platforms)", tag, indexDigest, len(manifests))
	return &Published{
		Reference: tag, Digest: indexDigest, Manifests: manifests, Layers: layers, Files: digests,
		Base: baseRef, Created: rev.LastModified,
	}, nil
}

// insecureIf carries a plain-HTTP registry (tests) into derived references.
func insecureIf(r name.Repository) name.Option {
	if r.Scheme() == "http" {
		return name.Insecure
	}
	return name.StrictValidation
}

// existing returns the publication already under the tag when it holds the
// specification's checkpoint, nil when the tag is free, and an error when the
// tag holds something else.
func existing(m *spec.ModelImage, tag name.Tag, opts []remote.Option) (*Published, error) {
	desc, err := remote.Get(tag, opts...)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("looking up %s: %w", tag, err)
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("%s exists and is not an image index: %w", tag, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	if im.Annotations[AnnotationRepository] != m.Spec.HuggingFace.Repository || im.Annotations[AnnotationRevision] != m.Spec.HuggingFace.Revision {
		return nil, fmt.Errorf("%s exists but holds %s@%s, not %s@%s: a tag is never re-pushed with other content",
			tag, im.Annotations[AnnotationRepository], im.Annotations[AnnotationRevision], m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision)
	}
	p := &Published{Reference: tag, Digest: desc.Digest, Manifests: map[string]v1.Hash{}, Base: im.Annotations[AnnotationBase], Existed: true}
	if created, err := time.Parse(time.RFC3339, im.Annotations["org.opencontainers.image.created"]); err == nil {
		p.Created = created
	}
	for _, d := range im.Manifests {
		if d.Platform != nil {
			p.Manifests[d.Platform.String()] = d.Digest
		}
	}
	if len(im.Manifests) > 0 {
		img, err := idx.Image(im.Manifests[0].Digest)
		if err != nil {
			return nil, err
		}
		layers, err := img.Layers()
		if err != nil {
			return nil, err
		}
		n := 1
		if v, err := strconv.Atoi(im.Annotations[AnnotationLayers]); err == nil && v > 0 && v <= len(layers) {
			n = v
		}
		for _, l := range layers[len(layers)-n:] {
			d, err := descriptor(l)
			if err != nil {
				return nil, err
			}
			p.Layers = append(p.Layers, d)
		}
	}
	return p, nil
}

func descriptor(l v1.Layer) (v1.Descriptor, error) {
	d, err := l.Digest()
	if err != nil {
		return v1.Descriptor{}, err
	}
	s, err := l.Size()
	if err != nil {
		return v1.Descriptor{}, err
	}
	mt, err := l.MediaType()
	if err != nil {
		return v1.Descriptor{}, err
	}
	return v1.Descriptor{MediaType: mt, Digest: d, Size: s}, nil
}

type base struct {
	platform v1.Platform
	image    v1.Image
}

// baseImages resolves the base image for every platform and pins the
// reference to its digest.
func baseImages(ctx context.Context, ref string, opts []remote.Option) ([]base, string, error) {
	baseRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, "", err
	}
	desc, err := remote.Get(baseRef, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("reading the base image %s: %w", ref, err)
	}
	var bases []base
	for _, p := range Platforms {
		img, err := remote.Image(baseRef, append(opts, remote.WithPlatform(p))...)
		if err != nil {
			return nil, "", fmt.Errorf("reading the base image %s for %s: %w", ref, p, err)
		}
		bases = append(bases, base{platform: p, image: img})
	}
	pinned := fmt.Sprintf("%s@%s", strings.SplitN(ref, "@", 2)[0], desc.Digest)
	return bases, pinned, nil
}

// streamLayers streams the checkpoint into the registry as uncompressed tar
// blobs of at most o.MaxLayerSize each, one after the other, and returns
// their descriptors and the per-file hashes.
func streamLayers(ctx context.Context, m *spec.ModelImage, files []hub.File, modTime time.Time, total int64, repo name.Repository, o Options) ([]v1.Descriptor, []FileDigest, error) {
	rt, err := transport.NewWithContext(ctx, repo.Registry, o.Auth, o.Transport, []string{repo.Scope(transport.PushScope)})
	if err != nil {
		return nil, nil, err
	}
	prog := &progress{total: total, started: time.Now(), log: o.Log}
	progCtx, stopProgress := context.WithCancel(ctx)
	defer stopProgress()
	go prog.run(progCtx, o.ProgressInterval)

	groups := groupFiles(files, o.MaxLayerSize)
	var digests []FileDigest
	var layers []v1.Descriptor
	var done int64
	for i, group := range groups {
		layer := &Layer{
			Repository: m.Spec.HuggingFace.Repository, Revision: m.Spec.HuggingFace.Revision,
			Files: group, ModTime: modTime, Root: spec.MountPath,
			Written: func(d FileDigest) { digests = append(digests, d) },
			Read:    func(n int) { prog.downloaded.Add(int64(n)) },
		}
		pr, pw := io.Pipe()
		go func() {
			_ = pw.CloseWithError(layer.WriteTo(ctx, pw, o.Hub))
		}()
		up := &registry.Uploader{
			Repository: repo, Transport: rt, ChunkSize: o.ChunkSize, Log: o.Log,
			Progress: func(n int64) { prog.uploaded.Store(done + n) },
		}
		res, err := up.Upload(ctx, pr)
		if err != nil {
			_ = pr.CloseWithError(err)
			return nil, nil, fmt.Errorf("streaming weights layer %d of %d: %w", i+1, len(groups), err)
		}
		done += res.Size
		layers = append(layers, v1.Descriptor{MediaType: types.OCIUncompressedLayer, Digest: res.Digest, Size: res.Size})
		o.Log("weights layer %d of %d, %s (%s, %d files), is in the registry", i+1, len(groups), res.Digest, humanBytes(res.Size), len(group))
	}
	stopProgress()
	prog.report()
	return layers, digests, nil
}

// groupFiles cuts the files, in path order, into runs of at most limit bytes;
// a file larger than the limit is a run of its own. The cut is a function of
// the file list alone, so every build of a revision yields the same layers.
func groupFiles(files []hub.File, limit int64) [][]hub.File {
	if limit <= 0 {
		limit = DefaultMaxLayerSize
	}
	sorted := append([]hub.File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	var groups [][]hub.File
	var current []hub.File
	var size int64
	for _, f := range sorted {
		if len(current) > 0 && size+f.Size > limit {
			groups = append(groups, current)
			current, size = nil, 0
		}
		current = append(current, f)
		size += f.Size
	}
	if len(current) > 0 {
		groups = append(groups, current)
	}
	return groups
}

// appendWeights adds the (already uploaded) weights layers to a base image and
// records the checkpoint in the config.
func appendWeights(b v1.Image, layers []v1.Descriptor, labels map[string]string, created time.Time, tool string, m *spec.ModelImage) (v1.Image, error) {
	var adds []mutate.Addendum
	for i, layer := range layers {
		adds = append(adds, mutate.Addendum{
			Layer: &existingLayer{desc: layer},
			History: v1.History{
				Created:   v1.Time{Time: created},
				CreatedBy: fmt.Sprintf("%s publish %s", tool, m.Metadata.Name),
				Comment:   fmt.Sprintf("%s@%s under /%s, layer %d of %d", m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision, spec.MountPath, i+1, len(layers)),
			},
		})
	}
	img, err := mutate.Append(b, adds...)
	if err != nil {
		return nil, err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	cfg := cf.Config
	if cfg.Labels == nil {
		cfg.Labels = map[string]string{}
	}
	for k, v := range labels {
		cfg.Labels[k] = v
	}
	img, err = mutate.Config(img, cfg)
	if err != nil {
		return nil, err
	}
	img, err = mutate.CreatedAt(img, v1.Time{Time: created})
	if err != nil {
		return nil, err
	}
	return mutate.ConfigMediaType(mutate.MediaType(img, types.OCIManifestSchema1), types.OCIConfigJSON), nil
}

// existingLayer is a layer whose blob the registry already holds: the writer
// checks for it by digest and never reads its content.
type existingLayer struct {
	desc v1.Descriptor
}

func (l *existingLayer) Digest() (v1.Hash, error)             { return l.desc.Digest, nil }
func (l *existingLayer) DiffID() (v1.Hash, error)             { return l.desc.Digest, nil }
func (l *existingLayer) Size() (int64, error)                 { return l.desc.Size, nil }
func (l *existingLayer) MediaType() (types.MediaType, error)  { return l.desc.MediaType, nil }
func (l *existingLayer) Compressed() (io.ReadCloser, error)   { return nil, errNotLocal }
func (l *existingLayer) Uncompressed() (io.ReadCloser, error) { return nil, errNotLocal }

var errNotLocal = errors.New("the weights layer lives in the registry; this process holds no copy")
