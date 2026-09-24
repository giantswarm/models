package hub

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHub serves one repository at one revision the way the Hub does: the model
// info, the recursive tree (in two pages) and the files with Range support.
type fakeHub struct {
	t        *testing.T
	repo     string
	rev      string
	files    map[string][]byte
	failures int32 // number of file requests to cut short before serving fully
	served   atomic.Int32
}

const (
	readme     = "README.md"
	weights    = "model.safetensors"
	nestedFile = "sub/vocab.json"
)

func (h *fakeHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models/"+h.repo+"/tree/"+h.rev, func(w http.ResponseWriter, r *http.Request) {
		names := []string{readme, "config.json", weights, nestedFile}
		page := r.URL.Query().Get("page")
		var entries []map[string]any
		var from, to int
		if page == "" {
			from, to = 0, 2
			w.Header().Set("Link", fmt.Sprintf(`<http://%s/api/models/%s/tree/%s?recursive=true&page=2>; rel="next"`, r.Host, h.repo, h.rev))
		} else {
			from, to = 2, 4
		}
		entries = append(entries, map[string]any{"type": "directory", "path": "sub"})
		for _, n := range names[from:to] {
			e := map[string]any{"type": "file", "path": n, "size": len(h.files[n])}
			if strings.HasSuffix(n, ".safetensors") {
				e["lfs"] = map[string]any{"oid": "deadbeef", "size": len(h.files[n])}
			}
			entries = append(entries, e)
		}
		_ = json.NewEncoder(w).Encode(entries)
	})
	mux.HandleFunc("/api/models/"+h.repo, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": h.rev, "lastModified": "2026-09-16T20:09:45.000Z"})
	})
	mux.HandleFunc("/"+h.repo+"/resolve/"+h.rev+"/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/"+h.repo+"/resolve/"+h.rev+"/")
		content, ok := h.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		n := h.served.Add(1)
		if r.Header.Get("Range") == "" && n <= h.failures {
			// A truncated 200: the client must notice and resume.
			w.Header().Set("Content-Length", fmt.Sprint(len(content)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(content[:len(content)/3])
			return
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(content))
	})
	return mux
}

func newFakeHub(t *testing.T, failures int32) (*fakeHub, *Client) {
	big := make([]byte, 3*1024*1024+17)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	h := &fakeHub{t: t, repo: "acme/tiny", rev: strings.Repeat("a", 40), failures: failures, files: map[string][]byte{
		readme:        []byte("# tiny\n"),
		"config.json": []byte(`{"model_type":"tiny"}`),
		weights:       big,
		nestedFile:    []byte(`{"version":"1.0"}`),
	}}
	srv := httptest.NewServer(h.handler())
	t.Cleanup(srv.Close)
	c := New("models-test")
	c.URL = srv.URL
	c.Backoff = time.Millisecond
	return h, c
}

func TestTreeAndRevision(t *testing.T) {
	h, c := newFakeHub(t, 0)
	ctx := context.Background()
	rev, err := c.Revision(ctx, h.repo, h.rev)
	if err != nil {
		t.Fatal(err)
	}
	if rev.LastModified.Format(time.RFC3339) != "2026-09-16T20:09:45Z" {
		t.Errorf("LastModified = %v", rev.LastModified)
	}
	files, err := c.Tree(ctx, h.repo, h.rev)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("Tree() = %d files, want 4 across two pages: %+v", len(files), files)
	}
	if files[0].Path != readme || files[3].Path != nestedFile {
		t.Errorf("files not sorted by path: %+v", files)
	}
	for _, f := range files {
		if f.Path == weights && f.SHA256 != "deadbeef" {
			t.Errorf("LFS hash not read: %+v", f)
		}
		if int(f.Size) != len(h.files[f.Path]) {
			t.Errorf("%s: size %d, want %d", f.Path, f.Size, len(h.files[f.Path]))
		}
	}
	if _, err := c.Revision(ctx, h.repo, strings.Repeat("b", 40)); err == nil {
		t.Error("a revision the Hub resolves to another commit must be refused")
	}
}

func TestOpenResumesTruncatedResponses(t *testing.T) {
	h, c := newFakeHub(t, 2)
	f := File{Path: weights, Size: int64(len(h.files[weights]))}
	got, err := io.ReadAll(c.Open(context.Background(), h.repo, h.rev, f))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, h.files[weights]) {
		t.Fatal("resumed content differs from the file")
	}
	if h.served.Load() < 2 {
		t.Errorf("expected at least one resumption, saw %d requests", h.served.Load())
	}
}

func TestOpenGivesUp(t *testing.T) {
	h, c := newFakeHub(t, 1000)
	c.Attempts = 3
	f := File{Path: weights, Size: int64(len(h.files[weights]))}
	// Every plain GET is truncated and the fake never sees a Range on a
	// truncated attempt because the client resumes with one -- so make the
	// resumptions fail too by pointing at a size the fake cannot satisfy.
	f.Size += 10
	_, err := io.ReadAll(c.Open(context.Background(), h.repo, h.rev, f))
	if err == nil {
		t.Fatal("expected the stream to fail when the file cannot be completed")
	}
}

func TestStatAndOpenAFileAtAURL(t *testing.T) {
	h, c := newFakeHub(t, 1)
	u := c.URL + "/" + h.repo + "/resolve/" + h.rev + "/" + weights
	ctx := context.Background()
	size, err := c.Stat(ctx, u)
	if err != nil || size != int64(len(h.files[weights])) {
		t.Fatalf("Stat() = %d, %v; want %d", size, err, len(h.files[weights]))
	}
	// The repository and revision are ignored for a file with a URL; a
	// truncated response resumes as it does for a file of the Hub.
	got, err := io.ReadAll(c.Open(ctx, "other/repo", "main", File{Path: "tiktoken/x", Size: size, URL: u}))
	if err != nil || !bytes.Equal(got, h.files[weights]) {
		t.Fatalf("Open(URL) = %d bytes, %v", len(got), err)
	}
	if _, err := c.Stat(ctx, c.URL+"/nowhere"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("Stat of a missing file: %v", err)
	}
}
