package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
)

// fakeRegistry implements the blob upload endpoints of the distribution spec
// with chunk accounting, and can fail the n-th PATCH after storing part of it.
type fakeRegistry struct {
	mu       sync.Mutex
	uploads  map[string][]byte
	blobs    map[string][]byte
	patches  int
	failAt   map[int]int // patch number -> bytes to keep before failing
	statuses int
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/blobs/uploads/"):
		id := fmt.Sprintf("u%d", len(f.uploads)+1)
		f.uploads[id] = nil
		w.Header().Set("Location", "/v2/x/blobs/uploads/"+id+"?_state=abc")
		w.WriteHeader(http.StatusAccepted)
	case r.Method == http.MethodPatch:
		id := strings.TrimPrefix(r.URL.Path, "/v2/x/blobs/uploads/")
		f.patches++
		var start, end int64
		if _, err := fmt.Sscanf(r.Header.Get("Content-Range"), "%d-%d", &start, &end); err != nil {
			http.Error(w, "bad Content-Range", http.StatusBadRequest)
			return
		}
		if start != int64(len(f.uploads[id])) {
			http.Error(w, fmt.Sprintf("have %d, got start %d", len(f.uploads[id]), start), http.StatusRequestedRangeNotSatisfiable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if keep, fail := f.failAt[f.patches]; fail {
			f.uploads[id] = append(f.uploads[id], body[:keep]...)
			http.Error(w, "flaky", http.StatusServiceUnavailable)
			return
		}
		f.uploads[id] = append(f.uploads[id], body...)
		w.Header().Set("Location", "/v2/x/blobs/uploads/"+id+"?_state="+strconv.Itoa(len(f.uploads[id])))
		w.Header().Set("Range", fmt.Sprintf("0-%d", len(f.uploads[id])-1))
		w.WriteHeader(http.StatusAccepted)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/uploads/"):
		id := strings.TrimPrefix(r.URL.Path, "/v2/x/blobs/uploads/")
		f.statuses++
		held := len(f.uploads[id])
		last := held - 1
		if held == 0 {
			last = 0
		}
		w.Header().Set("Location", "/v2/x/blobs/uploads/"+id+"?_state=status")
		w.Header().Set("Range", fmt.Sprintf("0-%d", last))
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPut:
		id := strings.TrimPrefix(r.URL.Path, "/v2/x/blobs/uploads/")
		sum := sha256.Sum256(f.uploads[id])
		digest := "sha256:" + hex.EncodeToString(sum[:])
		if got := r.URL.Query().Get("digest"); got != digest {
			http.Error(w, "digest mismatch "+got+" vs "+digest, http.StatusBadRequest)
			return
		}
		f.blobs[digest] = f.uploads[id]
		delete(f.uploads, id)
		w.WriteHeader(http.StatusCreated)
	default:
		http.NotFound(w, r)
	}
}

func newUploader(t *testing.T, f *fakeRegistry) *Uploader {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://")+"/x", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	return &Uploader{Repository: repo, Transport: http.DefaultTransport, ChunkSize: 1 << 20, Backoff: time.Millisecond}
}

func content(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUploadInChunks(t *testing.T) {
	f := &fakeRegistry{uploads: map[string][]byte{}, blobs: map[string][]byte{}}
	u := newUploader(t, f)
	var progress []int64
	u.Progress = func(n int64) { progress = append(progress, n) }
	data := content(t, 3<<20+123)
	res, err := u.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if res.Digest.Hex != hex.EncodeToString(sum[:]) || res.Size != int64(len(data)) {
		t.Fatalf("Upload() = %+v", res)
	}
	if !bytes.Equal(f.blobs[res.Digest.String()], data) {
		t.Fatal("the registry holds different bytes")
	}
	if f.patches != 4 || len(progress) != 4 || progress[3] != int64(len(data)) {
		t.Errorf("patches = %d, progress = %v", f.patches, progress)
	}
}

func TestUploadResumesAPartiallyStoredChunk(t *testing.T) {
	f := &fakeRegistry{uploads: map[string][]byte{}, blobs: map[string][]byte{}, failAt: map[int]int{2: 1000, 4: 0}}
	u := newUploader(t, f)
	data := content(t, 3<<20)
	res, err := u.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.blobs[res.Digest.String()], data) {
		t.Fatal("the registry holds different bytes after the resumptions")
	}
	if f.statuses != 2 {
		t.Errorf("expected two status reads, saw %d", f.statuses)
	}
}

func TestUploadGivesUp(t *testing.T) {
	f := &fakeRegistry{uploads: map[string][]byte{}, blobs: map[string][]byte{}, failAt: map[int]int{}}
	for i := 1; i < 20; i++ {
		f.failAt[i] = 0
	}
	u := newUploader(t, f)
	u.Attempts = 3
	if _, err := u.Upload(context.Background(), bytes.NewReader(content(t, 1<<20))); err == nil {
		t.Fatal("expected the upload to fail")
	}
}

func TestParseRange(t *testing.T) {
	for in, want := range map[string]int64{"0-0": 0, "0-99": 100, "bytes=0-1023": 1024} {
		got, err := parseRange(in)
		if err != nil || got != want {
			t.Errorf("parseRange(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := parseRange("5-9"); err == nil {
		t.Error("a range not starting at 0 must be refused")
	}
}
