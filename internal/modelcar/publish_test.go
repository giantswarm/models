package modelcar

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/giantswarm/models/internal/hub"
	"github.com/giantswarm/models/internal/spec"
)

const (
	testRepo = "acme/tiny"
	testRev  = "7c4f1bc1a2d6847e0cbc01ac6b823f00251de8dd"
	weights  = "model.safetensors"
)

// fakeHub serves one checkpoint the way the Hub does.
type fakeHub struct {
	files   map[string][]byte
	lfs     map[string]bool
	corrupt map[string]bool // files served with a flipped byte
}

func (h *fakeHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models/"+testRepo+"/tree/"+testRev, func(w http.ResponseWriter, r *http.Request) {
		var entries []map[string]any
		for name, content := range h.files {
			e := map[string]any{"type": "file", "path": name, "size": len(content)}
			if h.lfs[name] {
				sum := sha256.Sum256(content)
				e["lfs"] = map[string]any{"oid": hex.EncodeToString(sum[:]), "size": len(content)}
			}
			entries = append(entries, e)
		}
		_ = json.NewEncoder(w).Encode(entries)
	})
	mux.HandleFunc("/api/models/"+testRepo, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": testRev, "lastModified": "2026-09-16T20:09:45.000Z"})
	})
	mux.HandleFunc("/"+testRepo+"/resolve/"+testRev+"/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/"+testRepo+"/resolve/"+testRev+"/")
		content, ok := h.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if h.corrupt[name] {
			content = append([]byte(nil), content...)
			content[len(content)/2] ^= 0x55
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(content))
	})
	return mux
}

// pushBase publishes a two-platform base image to the test registry and
// returns its tag.
func pushBase(t *testing.T, reg string) string {
	t.Helper()
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	for _, p := range Platforms {
		layer := static.NewLayer([]byte("bin/sh for "+p.String()), types.OCILayer)
		img, err := mutate.AppendLayers(mutate.MediaType(mutate.ConfigMediaType(empty.Image, types.OCIConfigJSON), types.OCIManifestSchema1), layer)
		if err != nil {
			t.Fatal(err)
		}
		cf, _ := img.ConfigFile()
		cf.OS, cf.Architecture = p.OS, p.Architecture
		img, err = mutate.ConfigFile(img, cf)
		if err != nil {
			t.Fatal(err)
		}
		pp := p
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &pp}})
	}
	ref, err := name.NewTag(reg+"/base/busybox:1.0", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}
	return ref.String()
}

func setup(t *testing.T) (spec.ModelImage, Options, *fakeHub) {
	t.Helper()
	big := make([]byte, 3<<20+11)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	h := &fakeHub{files: map[string][]byte{
		"README.md":        []byte("# tiny\n"),
		"config.json":      []byte(`{"model_type":"tiny"}`),
		weights:            big,
		"sub/dir/tok.json": []byte(`{}`),
		"logo.png":         []byte("PNG"),
	}, lfs: map[string]bool{weights: true}}
	hubSrv := httptest.NewServer(h.handler())
	t.Cleanup(hubSrv.Close)
	client := hub.New("models-test")
	client.URL = hubSrv.URL

	regSrv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(regSrv.Close)
	regHost := strings.TrimPrefix(regSrv.URL, "http://")
	baseRef := pushBase(t, regHost)
	registry, err := name.NewRepository(regHost+"/giantswarm/models", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	m := spec.ModelImage{
		APIVersion: spec.APIVersion, Kind: spec.Kind,
		Metadata: spec.Metadata{Name: "tiny"},
		Spec: spec.Spec{
			HuggingFace: spec.HuggingFace{Repository: testRepo, Revision: testRev},
			Description: "A tiny model.", License: "apache-2.0", Base: baseRef,
		},
		Path: "models/tiny.yaml",
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	var logs []string
	o := Options{
		Registry: registry, Hub: client, Auth: authn.Anonymous, Source: "https://github.com/giantswarm/models",
		Tool: "models-test", ChunkSize: 1 << 20, ProgressInterval: time.Hour,
		Log: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)); t.Logf(f, a...) },
	}
	return m, o, h
}

func TestPublishBuildsATwoPlatformIndexWithUncompressedLayers(t *testing.T) {
	m, o, h := setup(t)
	ctx := context.Background()
	p, err := Publish(ctx, &m, o)
	if err != nil {
		t.Fatal(err)
	}
	if p.Existed {
		t.Fatal("first publication must build")
	}
	if p.Reference.TagStr() != "7c4f1bc1a2d6" || p.Annotations[AnnotationExtraFiles] != "" {
		t.Errorf("tag = %s", p.Reference.TagStr())
	}
	if len(p.Files) != 3 {
		t.Errorf("files in layer = %d (%+v), want config.json, model.safetensors and sub/dir/tok.json", len(p.Files), p.Files)
	}

	idx, err := remote.Index(p.Reference)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if im.MediaType != types.OCIImageIndex || len(im.Manifests) != 2 {
		t.Fatalf("index: %s with %d manifests", im.MediaType, len(im.Manifests))
	}
	if im.Annotations[AnnotationRevision] != testRev || im.Annotations[AnnotationRepository] != testRepo || im.Annotations[AnnotationFiles] != "3" {
		t.Errorf("index annotations: %v", im.Annotations)
	}
	var weightsDigests []v1.Hash
	for _, d := range im.Manifests {
		img, err := idx.Image(d.Digest)
		if err != nil {
			t.Fatal(err)
		}
		mf, err := img.Manifest()
		if err != nil {
			t.Fatal(err)
		}
		if mf.MediaType != types.OCIManifestSchema1 || mf.Config.MediaType != types.OCIConfigJSON {
			t.Errorf("%s: manifest %s config %s", d.Platform, mf.MediaType, mf.Config.MediaType)
		}
		if len(mf.Layers) != 2 || mf.Layers[1].MediaType != types.OCIUncompressedLayer {
			t.Fatalf("%s: layers %+v", d.Platform, mf.Layers)
		}
		weightsDigests = append(weightsDigests, mf.Layers[1].Digest)
		cf, err := img.ConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		if cf.Architecture != d.Platform.Architecture || cf.Config.Labels[AnnotationRevision] != testRev || len(cf.RootFS.DiffIDs) != 2 || cf.RootFS.DiffIDs[1] != mf.Layers[1].Digest {
			t.Errorf("%s: config %+v labels %v", d.Platform, cf.RootFS, cf.Config.Labels)
		}
		if !cf.Created.Equal(time.Date(2026, 9, 16, 20, 9, 45, 0, time.UTC)) {
			t.Errorf("created = %v, want the commit time", cf.Created)
		}
		if last := cf.History[len(cf.History)-1]; !strings.Contains(last.Comment, testRepo+"@"+testRev) {
			t.Errorf("history = %+v", last)
		}
		layers, err := img.Layers()
		if err != nil {
			t.Fatal(err)
		}
		rc, err := layers[1].Uncompressed()
		if err != nil {
			t.Fatal(err)
		}
		checkTar(t, rc, h)
	}
	if len(p.Layers) != 1 || weightsDigests[0] != weightsDigests[1] || weightsDigests[0] != p.Layers[0].Digest {
		t.Errorf("the platforms must share one weights layer: %v vs %v", weightsDigests, p.Layers)
	}
	if im.Annotations[AnnotationLayers] != "1" || im.Annotations[AnnotationWeights] != fmt.Sprint(p.Layers[0].Size) {
		t.Errorf("layer annotations: %v", im.Annotations)
	}

	again, err := Publish(ctx, &m, o)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Existed || again.Digest != p.Digest || len(again.Layers) != 1 || again.Layers[0].Digest != p.Layers[0].Digest {
		t.Errorf("second publication: existed=%v digest=%s layers=%v; want the first's %s / %v", again.Existed, again.Digest, again.Layers, p.Digest, p.Layers)
	}
	files, err := Files(ctx, &m, o.Hub)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(files) != fmt.Sprint(p.Files) {
		t.Errorf("Files() = %v, the build wrote %v", files, p.Files)
	}

	other := m
	other.Spec.HuggingFace.Revision = "7c4f1bc1a2d6" + strings.Repeat("0", 28)
	if _, err := Publish(ctx, &other, o); err == nil || !strings.Contains(err.Error(), "never re-pushed") {
		t.Errorf("a tag holding another revision must be refused, got %v", err)
	}
}

func TestPublishCutsTheWeightsIntoLayersUnderTheLimit(t *testing.T) {
	m, o, h := setup(t)
	o.MaxLayerSize = 2 << 20 // config.json | model.safetensors (3 MiB, alone) | sub/dir/tok.json
	ctx := context.Background()
	p, err := Publish(ctx, &m, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Layers) != 3 || len(p.Files) != 3 {
		t.Fatalf("layers = %v, files = %d", p.Layers, len(p.Files))
	}
	idx, err := remote.Index(p.Reference)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if im.Annotations[AnnotationLayers] != "3" {
		t.Errorf("annotations: %v", im.Annotations)
	}
	var total int64
	for _, l := range p.Layers {
		total += l.Size
	}
	if im.Annotations[AnnotationWeights] != fmt.Sprint(total) {
		t.Errorf("weights annotation %q, want %d", im.Annotations[AnnotationWeights], total)
	}
	for _, d := range im.Manifests {
		img, err := idx.Image(d.Digest)
		if err != nil {
			t.Fatal(err)
		}
		layers, err := img.Layers()
		if err != nil {
			t.Fatal(err)
		}
		if len(layers) != 4 {
			t.Fatalf("%s: %d layers", d.Platform, len(layers))
		}
		var names []string
		for i, l := range layers[1:] {
			rc, err := l.Uncompressed()
			if err != nil {
				t.Fatal(err)
			}
			entries := tarEntries(t, rc, h)
			if entries[0] != root {
				t.Errorf("layer %d starts with %q", i+1, entries[0])
			}
			names = append(names, entries...)
		}
		want := []string{root, "models/config.json", root, "models/model.safetensors", root, "models/sub/", "models/sub/dir/", "models/sub/dir/tok.json"}
		if strings.Join(names, ",") != strings.Join(want, ",") {
			t.Errorf("%s: entries across the layers = %v, want %v", d.Platform, names, want)
		}
		cf, err := img.ConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		if last := cf.History[len(cf.History)-1]; !strings.Contains(last.Comment, "layer 3 of 3") {
			t.Errorf("history = %+v", last)
		}
	}
	again, err := Publish(ctx, &m, o)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Existed || len(again.Layers) != 3 || again.Layers[2].Digest != p.Layers[2].Digest {
		t.Errorf("second publication: %+v", again)
	}
}

func TestGroupFiles(t *testing.T) {
	files := []hub.File{{Path: "b", Size: 5}, {Path: "a", Size: 5}, {Path: "c", Size: 20}, {Path: "d", Size: 1}, {Path: "e", Size: 9}}
	groups := groupFiles(files, 10)
	var got []string
	for _, g := range groups {
		var names []string
		for _, f := range g {
			names = append(names, f.Path)
		}
		got = append(got, strings.Join(names, "+"))
	}
	if want := "a+b,c,d+e"; strings.Join(got, ",") != want {
		t.Errorf("groupFiles = %v, want %s", got, want)
	}
	if n := len(groupFiles(files, 0)); n != 1 {
		t.Errorf("no limit: %d groups, want 1", n)
	}
}

func TestPublishRefusesACorruptedFile(t *testing.T) {
	m, o, h := setup(t)
	// The tree keeps the hash of the original bytes; the download serves others.
	h.corrupt = map[string]bool{weights: true}
	_, err := Publish(context.Background(), &m, o)
	if err == nil || !strings.Contains(err.Error(), "the Hub records sha256") {
		t.Fatalf("expected a hash mismatch, got %v", err)
	}
}

// checkTar reads the one weights layer back and checks its entries.
func checkTar(t *testing.T, rc io.ReadCloser, h *fakeHub) {
	t.Helper()
	names := tarEntries(t, rc, h)
	want := []string{root, "models/config.json", "models/model.safetensors", "models/sub/", "models/sub/dir/", "models/sub/dir/tok.json"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("tar entries = %v, want %v", names, want)
	}
}

// root is the directory entry every weights layer starts with.
const root = spec.MountPath + "/"

// tarEntries reads a weights layer back, checks every file against the Hub's
// content and returns the entry names in order.
func tarEntries(t *testing.T, rc io.ReadCloser, h *fakeHub) []string {
	t.Helper()
	defer func() { _ = rc.Close() }()
	tr := tar.NewReader(rc)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		if hdr.Typeflag == tar.TypeReg {
			content, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(content, h.files[strings.TrimPrefix(hdr.Name, root)]) {
				t.Errorf("%s: content differs", hdr.Name)
			}
			if hdr.Mode != 0o644 || hdr.Uid != 0 || !hdr.ModTime.Equal(time.Date(2026, 9, 16, 20, 9, 45, 0, time.UTC)) {
				t.Errorf("%s: mode %o uid %d mtime %v", hdr.Name, hdr.Mode, hdr.Uid, hdr.ModTime)
			}
		}
	}
	return names
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{512: "512 B", 1536: "1.5 KiB", 105895996845: "98.6 GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// withExtraFiles serves two extra files over TLS, adds them to the
// specification under tiktoken/ and points the Hub client's HTTP at a client
// that trusts the server (and still reaches the plain-HTTP fake Hub).
func withExtraFiles(t *testing.T, m *spec.ModelImage, o *Options) map[string][]byte {
	t.Helper()
	content := map[string][]byte{"o200k_base.tiktoken": []byte("bzIwMGs= 0\n"), "cl100k_base.tiktoken": []byte("Y2wxMDBr 0\nIQ== 1\n")}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/encodings/")
		c, ok := content[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(c))
	}))
	t.Cleanup(srv.Close)
	o.Hub.HTTP = srv.Client()
	for _, name := range []string{"o200k_base.tiktoken", "cl100k_base.tiktoken"} {
		sum := sha256.Sum256(content[name])
		m.Spec.ExtraFiles = append(m.Spec.ExtraFiles, spec.ExtraFile{
			URL: srv.URL + "/encodings/" + name, SHA256: hex.EncodeToString(sum[:]), Path: "tiktoken/" + name,
		})
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return content
}

func TestPublishAddsTheExtraFilesInALayerOfTheirOwn(t *testing.T) {
	m, o, h := setup(t)
	ctx := context.Background()
	plain, err := Publish(ctx, &m, o)
	if err != nil {
		t.Fatal(err)
	}
	extra := withExtraFiles(t, &m, &o)
	var logs []string
	o.Log = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)); t.Logf(f, a...) }

	p, err := Publish(ctx, &m, o)
	if err != nil {
		t.Fatal(err)
	}
	if p.Existed || p.Reference.TagStr() != m.Tag() || !strings.HasPrefix(p.Reference.TagStr(), "7c4f1bc1a2d6-") {
		t.Fatalf("published %s (existed %v), want the new tag %s", p.Reference, p.Existed, m.Tag())
	}
	if !strings.Contains(strings.Join(logs, "\n"), "they are reused, not streamed") {
		t.Errorf("the checkpoint's layer must be reused from %s: %v", plain.Reference, logs)
	}
	if len(p.Layers) != 2 || p.Layers[0].Digest != plain.Layers[0].Digest || p.Layers[0].Size != plain.Layers[0].Size {
		t.Fatalf("layers = %v, want the checkpoint's %v plus one", p.Layers, plain.Layers)
	}
	if len(p.Files) != 5 || p.Files[3].Path != "models/tiktoken/cl100k_base.tiktoken" || p.Files[3].URL == "" || p.Files[0].URL != "" {
		t.Errorf("files = %+v", p.Files)
	}

	idx, err := remote.Index(p.Reference)
	if err != nil {
		t.Fatal(err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if im.Annotations[AnnotationExtraFiles] != m.ExtraFilesDigest() || im.Annotations[AnnotationFiles] != "5" || im.Annotations[AnnotationLayers] != "2" {
		t.Errorf("index annotations: %v", im.Annotations)
	}
	img, err := idx.Image(im.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := layers[2].Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range extra {
		h.files["tiktoken/"+name] = c // what tarEntries compares the layer against
	}
	want := []string{root, "models/tiktoken/", "models/tiktoken/cl100k_base.tiktoken", "models/tiktoken/o200k_base.tiktoken"}
	if got := tarEntries(t, rc, h); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("extra layer entries = %v, want %v", got, want)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	if last := cf.History[len(cf.History)-1]; !strings.Contains(last.Comment, "extra files") || !strings.Contains(last.Comment, "layer 2 of 2") {
		t.Errorf("history = %+v", last)
	}
	for name := range extra {
		delete(h.files, "tiktoken/"+name)
	}

	files, err := Files(ctx, &m, o.Hub)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(files) != fmt.Sprint(p.Files) {
		t.Errorf("Files() = %v, the build wrote %v", files, p.Files)
	}
	again, err := Publish(ctx, &m, o)
	if err != nil || !again.Existed || again.Digest != p.Digest {
		t.Errorf("second publication: %+v, %v", again, err)
	}
	// The checkpoint's own tag is untouched.
	if d, err := remote.Head(plain.Reference); err != nil || d.Digest != plain.Digest {
		t.Errorf("%s moved: %v %v", plain.Reference, d, err)
	}
}

func TestPublishWithExtraFilesIsTheSameImageWithoutACheckpointImage(t *testing.T) {
	// Where the checkpoint's image exists, its layers are reused; where it
	// does not, the checkpoint is streamed. Both are the same image.
	m, o, _ := setup(t)
	ctx := context.Background()
	if _, err := Publish(ctx, &m, o); err != nil {
		t.Fatal(err)
	}
	withExtraFiles(t, &m, &o)
	reused, err := Publish(ctx, &m, o)
	if err != nil {
		t.Fatal(err)
	}

	fresh, err := name.NewRepository(o.Registry.RegistryStr()+"/fresh/models", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	o.Registry = fresh
	var logs []string
	o.Log = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	built, err := Publish(ctx, &m, o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(logs, "\n"), "reused") || len(built.Layers) != 2 {
		t.Errorf("without a checkpoint image both layers must be streamed: %v, %v", built.Layers, logs)
	}
	if built.Digest != reused.Digest || fmt.Sprint(built.Files) != fmt.Sprint(reused.Files) {
		t.Errorf("built %s with %v, reused %s with %v: the same specification must give the same image", built.Digest, built.Files, reused.Digest, reused.Files)
	}
}

func TestPublishStreamsTheCheckpointWhenItsImageIsCutDifferently(t *testing.T) {
	m, o, _ := setup(t)
	ctx := context.Background()
	o.MaxLayerSize = 2 << 20
	if _, err := Publish(ctx, &m, o); err != nil {
		t.Fatal(err)
	}
	withExtraFiles(t, &m, &o)
	o.MaxLayerSize = 0
	var logs []string
	o.Log = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	p, err := Publish(ctx, &m, o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "the checkpoint is streamed") || len(p.Layers) != 2 {
		t.Errorf("a checkpoint image in 3 layers must not be reused for a build of 1: %v, %v", p.Layers, logs)
	}
}

func TestPublishRefusesAnExtraFileWithOtherBytes(t *testing.T) {
	m, o, _ := setup(t)
	withExtraFiles(t, &m, &o)
	m.Spec.ExtraFiles[1].SHA256 = strings.Repeat("0", 64)
	_, err := Publish(context.Background(), &m, o)
	if err == nil || !strings.Contains(err.Error(), "the specification pins sha256:"+strings.Repeat("0", 64)) {
		t.Fatalf("expected a hash mismatch, got %v", err)
	}
	_, extra, err := Contents(context.Background(), &m, o.Hub)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyExtraFiles(context.Background(), o.Hub, &m, extra); err == nil || !strings.Contains(err.Error(), "the specification pins") {
		t.Errorf("VerifyExtraFiles: expected a hash mismatch, got %v", err)
	}
}

func TestContentsRefusesAnExtraFileOnTheCheckpoint(t *testing.T) {
	m, o, _ := setup(t)
	withExtraFiles(t, &m, &o)
	ctx := context.Background()
	for p, want := range map[string]string{
		"config.json":        "has a file or directory at that path",
		"sub/dir":            "has a file or directory at that path",
		"config.json/x":      "has a file at config.json",
		"README.md":          "", // excluded from the image: free
		"sub/dir/extra.json": "", // beside a checkpoint file: fine
	} {
		m.Spec.ExtraFiles[0].Path = p
		_, _, err := Contents(ctx, &m, o.Hub)
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: got %v, want %q", p, err, want)
		}
	}
}

func TestLayerSizeIsTheStreamedSize(t *testing.T) {
	m, o, _ := setup(t)
	o.MaxLayerSize = 2 << 20
	p, err := Publish(context.Background(), &m, o)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, _, err := Contents(context.Background(), &m, o.Hub)
	if err != nil {
		t.Fatal(err)
	}
	for i, g := range groupFiles(checkpoint, o.MaxLayerSize) {
		size, err := (&Layer{Files: g, ModTime: p.Created, Root: spec.MountPath}).Size()
		if err != nil || size != p.Layers[i].Size {
			t.Errorf("layer %d: Size() = %d, %v; streamed %d", i+1, size, err, p.Layers[i].Size)
		}
	}
}
