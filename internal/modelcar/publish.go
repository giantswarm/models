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
	// AnnotationExtraFiles is the specification's ExtraFilesDigest; absent on
	// an image without extra files.
	AnnotationExtraFiles = "io.giantswarm.models.extra-files"
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
	// Annotations are the index annotations.
	Annotations map[string]string
}

// Publish builds the image for a specification and pushes it, or finds it
// already there. The weights never touch local disk: each file streams from
// the Hub (an extra file from its URL) through the tar writer into the
// registry's blob upload. An image with extra files streams the checkpoint
// only when the checkpoint's own image does not hold the same layers.
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
	checkpoint, extra, err := Contents(ctx, m, o.Hub)
	if err != nil {
		return nil, err
	}
	if len(checkpoint) == 0 {
		return nil, fmt.Errorf("%s: every file of the checkpoint is excluded", m.Path)
	}

	bases, baseRef, err := baseImages(ctx, m.Base(), remoteOpts)
	if err != nil {
		return nil, err
	}

	var extraNote string
	if len(extra) > 0 {
		extraNote = fmt.Sprintf(" and %d extra files, %s", len(extra), humanBytes(totalSize(extra)))
	}
	o.Log("building %s from %s@%s: %d files, %s%s, base %s", tag, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision,
		len(checkpoint), humanBytes(totalSize(checkpoint)), extraNote, baseRef)
	groups := groupFiles(checkpoint, o.MaxLayerSize)
	layers, err := publishedCheckpoint(m, repo, checkpoint, groups, rev.LastModified, remoteOpts, o.Log)
	if err != nil {
		return nil, err
	}
	var digests []FileDigest
	var stream [][]hub.File
	if layers == nil {
		stream = groups
	} else if digests, err = checkpointDigests(ctx, m, o.Hub, checkpoint); err != nil {
		return nil, err
	}
	stream = append(stream, groupFiles(extra, o.MaxLayerSize)...)
	streamed, streamedDigests, err := streamLayers(ctx, m, stream, rev.LastModified, repo, o)
	if err != nil {
		return nil, err
	}
	layers = append(layers, streamed...)
	digests = append(digests, streamedDigests...)
	var weights int64
	for _, l := range layers {
		weights += l.Size
	}
	comments := make([]string, len(layers))
	for i := range layers {
		what := fmt.Sprintf("%s@%s", m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision)
		if i >= len(groups) {
			what = "the specification's extra files"
		}
		comments[i] = fmt.Sprintf("%s under /%s, layer %d of %d", what, spec.MountPath, i+1, len(layers))
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
		AnnotationFiles:                        fmt.Sprint(len(checkpoint) + len(extra)),
		AnnotationWeights:                      fmt.Sprint(weights),
		AnnotationLayers:                       fmt.Sprint(len(layers)),
		AnnotationBase:                         baseRef,
		AnnotationExtraFiles:                   m.ExtraFilesDigest(),
	}
	for k, v := range labels {
		if v == "" {
			delete(labels, k)
		}
	}

	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	manifests := map[string]v1.Hash{}
	for _, b := range bases {
		img, err := appendWeights(b.image, layers, comments, labels, rev.LastModified, o.Tool, m)
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
		Base: baseRef, Created: rev.LastModified, Annotations: labels,
	}, nil
}

func totalSize(files []hub.File) int64 {
	var n int64
	for _, f := range files {
		n += f.Size
	}
	return n
}

// publishedCheckpoint returns the checkpoint's layers as the image under the
// checkpoint's own tag holds them, for an image with extra files: that image
// is the same checkpoint, and when it holds the same files cut into layers of
// the same sizes as this build's, its layer blobs are the ones this build would
// stream, already in the repository. The image with extra files then adds its
// extra layers to them and streams nothing of the checkpoint again. Nil when
// the specification has no extra files, there is no such image, or its layers
// differ from this build's.
func publishedCheckpoint(m *spec.ModelImage, repo name.Repository, checkpoint []hub.File, groups [][]hub.File, modTime time.Time, opts []remote.Option, log func(string, ...any)) ([]v1.Descriptor, error) {
	if len(m.Spec.ExtraFiles) == 0 {
		return nil, nil
	}
	plain := *m
	plain.Spec.ExtraFiles = nil
	tag := repo.Tag(plain.Tag())
	p, err := existing(&plain, tag, opts)
	if err != nil || p == nil {
		return nil, err
	}
	if files := p.Annotations[AnnotationFiles]; files != fmt.Sprint(len(checkpoint)) || len(p.Layers) != len(groups) {
		log("%s holds %s files in %d layers, this build cuts %d files into %d; the checkpoint is streamed", tag, files, len(p.Layers), len(checkpoint), len(groups))
		return nil, nil
	}
	for i, g := range groups {
		size, err := (&Layer{Files: g, ModTime: modTime, Root: spec.MountPath}).Size()
		if err != nil {
			return nil, err
		}
		if l := p.Layers[i]; l.MediaType != types.OCIUncompressedLayer || l.Size != size {
			log("%s layer %d is %s of %d bytes, this build's is %d; the checkpoint is streamed", tag, i+1, l.MediaType, l.Size, size)
			return nil, nil
		}
	}
	log("%s holds this checkpoint in the same %d layers; they are reused, not streamed", tag, len(groups))
	return p.Layers, nil
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
	if got, want := im.Annotations[AnnotationExtraFiles], m.ExtraFilesDigest(); got != want {
		return nil, fmt.Errorf("%s exists but holds the extra files %q, not %q: a tag is never re-pushed with other content", tag, got, want)
	}
	p := &Published{Reference: tag, Digest: desc.Digest, Manifests: map[string]v1.Hash{}, Base: im.Annotations[AnnotationBase], Existed: true, Annotations: im.Annotations}
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

// streamLayers streams groups of files into the registry as uncompressed tar
// blobs, one after the other, and returns their descriptors and the per-file
// hashes. A file carries its source: the checkpoint at the revision, or an
// extra file's URL.
func streamLayers(ctx context.Context, m *spec.ModelImage, groups [][]hub.File, modTime time.Time, repo name.Repository, o Options) ([]v1.Descriptor, []FileDigest, error) {
	if len(groups) == 0 {
		return nil, nil, nil
	}
	rt, err := transport.NewWithContext(ctx, repo.Registry, o.Auth, o.Transport, []string{repo.Scope(transport.PushScope)})
	if err != nil {
		return nil, nil, err
	}
	var total int64
	for _, g := range groups {
		total += totalSize(g)
	}
	prog := &progress{total: total, started: time.Now(), log: o.Log}
	progCtx, stopProgress := context.WithCancel(ctx)
	defer stopProgress()
	go prog.run(progCtx, o.ProgressInterval)

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
			return nil, nil, fmt.Errorf("streaming layer %d of %d: %w", i+1, len(groups), err)
		}
		done += res.Size
		layers = append(layers, v1.Descriptor{MediaType: types.OCIUncompressedLayer, Digest: res.Digest, Size: res.Size})
		o.Log("layer %d of %d streamed, %s (%s, %d files), is in the registry", i+1, len(groups), res.Digest, humanBytes(res.Size), len(group))
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

// appendWeights adds the (already uploaded) weights layers, each with its
// history comment, to a base image and records the checkpoint in the config.
func appendWeights(b v1.Image, layers []v1.Descriptor, comments []string, labels map[string]string, created time.Time, tool string, m *spec.ModelImage) (v1.Image, error) {
	var adds []mutate.Addendum
	for i, layer := range layers {
		adds = append(adds, mutate.Addendum{
			Layer: &existingLayer{desc: layer},
			History: v1.History{
				Created:   v1.Time{Time: created},
				CreatedBy: fmt.Sprintf("%s publish %s", tool, m.Metadata.Name),
				Comment:   comments[i],
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
