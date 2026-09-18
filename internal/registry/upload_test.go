package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
// with chunk accounting. It can fail the n-th PATCH after storing part of it,
// answer the commit PUTs with a list of statuses, and -- like a registry whose
// gateway gave up on a commit it kept working on -- turn the upload into the
// blob on the n-th HEAD for it.
type fakeRegistry struct {
	mu       sync.Mutex
	uploads  map[string][]byte
	blobs    map[string][]byte
	patches  int
	failAt   map[int]int // patch number -> bytes to keep before failing
	statuses int

	puts, heads, deletes int
	commitStatuses       []int             // answers to successive PUTs before the real commit
	dropUploadOnFail     bool              // a failed PUT also discards the upload
	finalizeOnHead       int               // the HEAD that turns a pending upload into the blob
	finalizeOnPut        int               // the PUT before which a pending upload turns into the blob
	pending              map[string]string // digest -> upload id, after a failed PUT
}

// finalize turns every upload a failed PUT left pending into its blob.
func (f *fakeRegistry) finalize() {
	for digest, id := range f.pending {
		f.blobs[digest] = f.uploads[id]
		delete(f.uploads, id)
		delete(f.pending, digest)
	}
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{uploads: map[string][]byte{}, blobs: map[string][]byte{}, pending: map[string]string{}}
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
		f.puts++
		if f.finalizeOnPut > 0 && f.puts >= f.finalizeOnPut {
			f.finalize()
		}
		if _, ok := f.uploads[id]; !ok {
			http.NotFound(w, r)
			return
		}
		sum := sha256.Sum256(f.uploads[id])
		digest := "sha256:" + hex.EncodeToString(sum[:])
		if got := r.URL.Query().Get("digest"); got != digest {
			http.Error(w, "digest mismatch "+got+" vs "+digest, http.StatusBadRequest)
			return
		}
		if len(f.commitStatuses) > 0 {
			status := f.commitStatuses[0]
			f.commitStatuses = f.commitStatuses[1:]
			if status >= 500 {
				f.pending[digest] = id
			}
			if f.dropUploadOnFail {
				delete(f.uploads, id)
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		f.blobs[digest] = f.uploads[id]
		delete(f.uploads, id)
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/blobs/sha256:"):
		f.heads++
		if f.finalizeOnHead > 0 && f.heads >= f.finalizeOnHead {
			f.finalize()
		}
		digest := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		blob, ok := f.blobs[digest]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/v2/x/blobs/uploads/")
		f.deletes++
		if _, ok := f.uploads[id]; !ok {
			http.NotFound(w, r)
			return
		}
		delete(f.uploads, id)
		w.WriteHeader(http.StatusAccepted)
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
	return &Uploader{
		Repository: repo, Transport: http.DefaultTransport, ChunkSize: 1 << 20, Backoff: time.Millisecond,
		PollInterval: time.Millisecond, FinalizeWait: 30 * time.Millisecond,
	}
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
	f := newFakeRegistry()
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
	f := newFakeRegistry()
	f.failAt = map[int]int{2: 1000, 4: 0}
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
	f := newFakeRegistry()
	f.failAt = map[int]int{}
	for i := 1; i < 20; i++ {
		f.failAt[i] = 0
	}
	u := newUploader(t, f)
	u.Attempts = 3
	if _, err := u.Upload(context.Background(), bytes.NewReader(content(t, 1<<20))); err == nil {
		t.Fatal("expected the upload to fail")
	}
}

func TestUploadCommitOutlivesAGatewayTimeout(t *testing.T) {
	// The PUT gets 504 while the registry keeps finalizing; the blob appears
	// on a later poll and no second PUT is sent.
	f := newFakeRegistry()
	f.commitStatuses = []int{http.StatusGatewayTimeout}
	f.finalizeOnHead = 3 // 1: the check before the PUT, 2 and 3: polls
	u := newUploader(t, f)
	data := content(t, 2<<20)
	res, err := u.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.blobs[res.Digest.String()], data) {
		t.Fatal("the registry holds different bytes")
	}
	if f.puts != 1 || f.heads < 3 {
		t.Errorf("puts = %d, heads = %d", f.puts, f.heads)
	}
}

func TestUploadRetriesTheCommitWhileTheUploadExists(t *testing.T) {
	// The blob never appears after the 504, the upload still holds every
	// byte: the commit is tried again and succeeds.
	f := newFakeRegistry()
	f.commitStatuses = []int{http.StatusGatewayTimeout}
	u := newUploader(t, f)
	var lines []string
	u.Log = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	data := content(t, 1<<20+7)
	res, err := u.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.blobs[res.Digest.String()], data) {
		t.Fatal("the registry holds different bytes")
	}
	if f.puts != 2 || f.statuses != 1 {
		t.Errorf("puts = %d, status reads = %d", f.puts, f.statuses)
	}
	if len(lines) < 3 || !strings.Contains(lines[0], res.Digest.String()) {
		t.Errorf("the log does not name the digest before the commit: %q", lines)
	}
}

func TestUploadFailsWhenTheRegistryDropsTheUpload(t *testing.T) {
	f := newFakeRegistry()
	f.commitStatuses = []int{http.StatusGatewayTimeout}
	f.dropUploadOnFail = true
	u := newUploader(t, f)
	_, err := u.Upload(context.Background(), bytes.NewReader(content(t, 1<<20)))
	if err == nil || !strings.Contains(err.Error(), "did not appear") {
		t.Fatalf("err = %v", err)
	}
	if f.puts != 1 {
		t.Errorf("puts = %d", f.puts)
	}
}

func TestUploadGivesUpOnTheCommit(t *testing.T) {
	f := newFakeRegistry()
	f.commitStatuses = []int{http.StatusGatewayTimeout, http.StatusBadGateway}
	u := newUploader(t, f)
	u.CommitAttempts = 2
	_, err := u.Upload(context.Background(), bytes.NewReader(content(t, 1<<20)))
	if err == nil || !strings.Contains(err.Error(), "giving up on the commit after 2 attempts") {
		t.Fatalf("err = %v", err)
	}
	if f.puts != 2 {
		t.Errorf("puts = %d", f.puts)
	}
}

func TestUploadDoesNotWaitOnAPermanentCommitError(t *testing.T) {
	f := newFakeRegistry()
	f.commitStatuses = []int{http.StatusBadRequest}
	u := newUploader(t, f)
	u.FinalizeWait = time.Hour
	done := make(chan error, 1)
	go func() {
		_, err := u.Upload(context.Background(), bytes.NewReader(content(t, 1<<20)))
		done <- err
	}()
	select {
	case err := <-done:
		var se *StatusError
		if !errors.As(err, &se) || se.Status != http.StatusBadRequest {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a 400 on the commit waited for the blob")
	}
	if f.heads != 2 || f.puts != 1 {
		t.Errorf("heads = %d, puts = %d", f.heads, f.puts)
	}
}

func TestUploadRetriedCommitFindsTheBlobLanded(t *testing.T) {
	// The first commit got 504; the second finds the upload gone (404)
	// because the registry finished the first one in the meantime.
	f := newFakeRegistry()
	f.commitStatuses = []int{http.StatusGatewayTimeout}
	f.finalizeOnHead = 1 << 30 // never on a poll
	f.finalizeOnPut = 2        // on the second commit, before answering it
	u := newUploader(t, f)
	data := content(t, 1<<20+1)
	res, err := u.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.blobs[res.Digest.String()], data) || f.puts != 2 {
		t.Errorf("puts = %d", f.puts)
	}
}

func TestUploadSkipsTheCommitOfABlobTheRegistryHolds(t *testing.T) {
	// The same bytes were committed by an earlier run whose PUT got a 504:
	// the upload is discarded instead of committed.
	f := newFakeRegistry()
	data := content(t, 1<<20+3)
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	f.blobs[digest] = data
	u := newUploader(t, f)
	res, err := u.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if res.Digest.String() != digest || f.puts != 0 || f.deletes != 1 || len(f.uploads) != 0 {
		t.Errorf("res = %+v, puts = %d, deletes = %d, uploads left = %d", res, f.puts, f.deletes, len(f.uploads))
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
