// Package hub reads a Hugging Face repository at a pinned revision: the file
// list with sizes and hashes, and each file as a stream that resumes where a
// connection dropped.
package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultURL is the public Hub.
const DefaultURL = "https://huggingface.co"

// Client reads one Hub. The zero value is not usable; use New.
type Client struct {
	// URL is the Hub's base URL, without a trailing slash.
	URL string
	// HTTP performs the requests. Its timeout must be zero: a download runs for
	// as long as the file is; stalls are caught by StallTimeout instead.
	HTTP *http.Client
	// UserAgent identifies the tool to the Hub.
	UserAgent string
	// StallTimeout ends a read that makes no progress for this long; the read is
	// then resumed with a Range request.
	StallTimeout time.Duration
	// Attempts bounds the resumptions of one file.
	Attempts int
	// Backoff waits before a resumption; the wait doubles per attempt.
	Backoff time.Duration
}

// New returns a client for the public Hub with the production limits.
func New(userAgent string) *Client {
	return &Client{
		URL:          DefaultURL,
		HTTP:         &http.Client{Transport: transport()},
		UserAgent:    userAgent,
		StallTimeout: 2 * time.Minute,
		Attempts:     8,
		Backoff:      2 * time.Second,
	}
}

func transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = 2 * time.Minute
	t.MaxIdleConnsPerHost = 4
	return t
}

// File is one regular file of the repository.
type File struct {
	// Path is the file's path in the repository.
	Path string
	// Size is the file's size in bytes.
	Size int64
	// SHA256 is the hash the Hub stores for an LFS file; empty for a file the
	// Hub keeps in git directly (the small configuration files).
	SHA256 string
}

// Revision is a commit of the repository.
type Revision struct {
	SHA          string
	LastModified time.Time
}

type treeEntry struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	LFS  *struct {
		OID  string `json:"oid"`
		Size int64  `json:"size"`
	} `json:"lfs"`
}

// Revision resolves a commit of the repository and checks it is the one asked for.
func (c *Client) Revision(ctx context.Context, repository, revision string) (Revision, error) {
	var info struct {
		SHA          string    `json:"sha"`
		LastModified time.Time `json:"lastModified"`
	}
	u := fmt.Sprintf("%s/api/models/%s?revision=%s", c.URL, repository, url.PathEscape(revision))
	if err := c.getJSON(ctx, u, &info); err != nil {
		return Revision{}, err
	}
	if info.SHA != revision {
		return Revision{}, fmt.Errorf("%s: the Hub resolves %s to commit %s", repository, revision, info.SHA)
	}
	if info.LastModified.IsZero() {
		return Revision{}, fmt.Errorf("%s@%s: the Hub reports no commit date", repository, revision)
	}
	return Revision{SHA: info.SHA, LastModified: info.LastModified.UTC()}, nil
}

// Tree lists the repository's files at the revision, sorted by path.
func (c *Client) Tree(ctx context.Context, repository, revision string) ([]File, error) {
	next := fmt.Sprintf("%s/api/models/%s/tree/%s?recursive=true", c.URL, repository, url.PathEscape(revision))
	var files []File
	for next != "" {
		var entries []treeEntry
		link, err := c.getJSONPage(ctx, next, &entries)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Type != "file" {
				continue
			}
			f := File{Path: e.Path, Size: e.Size}
			if e.LFS != nil {
				f.SHA256 = e.LFS.OID
				if e.LFS.Size != 0 {
					f.Size = e.LFS.Size
				}
			}
			files = append(files, f)
		}
		next = link
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s@%s: the Hub lists no files", repository, revision)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// Open streams one file of the revision. Reads that fail or stall are resumed
// from the last byte delivered; the stream ends with an error if the Hub
// delivers a different number of bytes than the file has.
func (c *Client) Open(ctx context.Context, repository, revision string, f File) io.ReadCloser {
	return &resumingReader{
		client: c,
		ctx:    ctx,
		url:    fmt.Sprintf("%s/%s/resolve/%s/%s", c.URL, repository, url.PathEscape(revision), escapePath(f.Path)),
		name:   fmt.Sprintf("%s@%s:%s", repository, revision, f.Path),
		size:   f.Size,
	}
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

func (c *Client) getJSON(ctx context.Context, u string, into any) error {
	_, err := c.getJSONPage(ctx, u, into)
	return err
}

var nextLinkRE = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// getJSONPage fetches one JSON document and returns the URL of the next page
// when the response carries a Link: <…>; rel="next" header.
func (c *Client) getJSONPage(ctx context.Context, u string, into any) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("GET %s: %s: %s", u, resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return "", fmt.Errorf("GET %s: %w", u, err)
	}
	if m := nextLinkRE.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
		return m[1], nil
	}
	return "", nil
}

// resumingReader is one file's stream across as many HTTP requests as it takes.
type resumingReader struct {
	client *Client
	ctx    context.Context
	url    string
	name   string
	size   int64

	offset   int64
	attempts int
	body     io.ReadCloser
	cancel   context.CancelFunc
	stall    *time.Timer
	closed   bool
}

// ErrShortFile reports a stream that ended before the file's size.
var ErrShortFile = errors.New("the Hub delivered fewer bytes than the file has")

func (r *resumingReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, errors.New("read on a closed file stream")
	}
	if r.offset >= r.size {
		return 0, io.EOF
	}
	for {
		if r.body == nil {
			if err := r.open(); err != nil {
				return 0, err
			}
		}
		if remaining := r.size - r.offset; int64(len(p)) > remaining {
			p = p[:remaining]
		}
		n, err := r.body.Read(p)
		r.offset += int64(n)
		if n > 0 {
			r.stall.Reset(r.client.StallTimeout)
		}
		switch {
		case err == nil:
			return n, nil
		case err == io.EOF && r.offset == r.size:
			r.dropBody()
			return n, io.EOF
		case err == io.EOF:
			// A truncated response: resume the rest.
			err = fmt.Errorf("%s: %w at byte %d", r.name, ErrShortFile, r.offset)
			fallthrough
		default:
			r.dropBody()
			if n > 0 {
				// Deliver what arrived; the next Read resumes.
				return n, nil
			}
			if retryErr := r.retry(err); retryErr != nil {
				return 0, retryErr
			}
		}
	}
}

// retry waits before the next attempt or returns the error that ends the stream.
func (r *resumingReader) retry(cause error) error {
	r.attempts++
	if r.attempts >= r.client.Attempts {
		return fmt.Errorf("%s: giving up after %d attempts: %w", r.name, r.attempts, cause)
	}
	wait := r.client.Backoff << (r.attempts - 1)
	select {
	case <-r.ctx.Done():
		return r.ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

func (r *resumingReader) open() error {
	ctx, cancel := context.WithCancel(r.ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		cancel()
		return err
	}
	req.Header.Set("User-Agent", r.client.UserAgent)
	if r.offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", r.offset))
	}
	resp, err := r.client.HTTP.Do(req)
	if err != nil {
		cancel()
		return r.retryOrFail(fmt.Errorf("%s: %w", r.name, err))
	}
	switch {
	case r.offset == 0 && resp.StatusCode == http.StatusOK:
		if resp.ContentLength >= 0 && resp.ContentLength != r.size {
			_ = resp.Body.Close()
			cancel()
			return fmt.Errorf("%s: the Hub serves %d bytes, the tree lists %d", r.name, resp.ContentLength, r.size)
		}
	case r.offset > 0 && resp.StatusCode == http.StatusPartialContent:
		if !strings.HasPrefix(resp.Header.Get("Content-Range"), fmt.Sprintf("bytes %d-", r.offset)) {
			_ = resp.Body.Close()
			cancel()
			return fmt.Errorf("%s: asked for bytes %d-, the Hub answered %q", r.name, r.offset, resp.Header.Get("Content-Range"))
		}
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		cancel()
		err := fmt.Errorf("%s: GET at byte %d: %s: %s", r.name, r.offset, resp.Status, strings.TrimSpace(string(body)))
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return r.retryOrFail(err)
		}
		return err
	}
	r.body = resp.Body
	r.cancel = cancel
	r.stall = time.AfterFunc(r.client.StallTimeout, cancel)
	return nil
}

// retryOrFail retries a failed open or returns its error; a successful retry
// re-enters open from Read's loop.
func (r *resumingReader) retryOrFail(cause error) error {
	if err := r.retry(cause); err != nil {
		return err
	}
	return r.open()
}

func (r *resumingReader) dropBody() {
	if r.stall != nil {
		r.stall.Stop()
	}
	if r.body != nil {
		_ = r.body.Close()
	}
	if r.cancel != nil {
		r.cancel()
	}
	r.body, r.cancel, r.stall = nil, nil, nil
}

// Close ends the stream.
func (r *resumingReader) Close() error {
	r.closed = true
	r.dropBody()
	return nil
}

// ParseSize reads a decimal byte count header value.
func ParseSize(s string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
}
