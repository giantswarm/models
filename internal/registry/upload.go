// Package registry uploads one blob to an OCI registry in resumable chunks:
// the weights layer of a model image is tens of gigabytes long and streams
// straight from the Hub, so a dropped connection must cost one chunk, not the
// whole transfer, and the registry's own finalization of the blob -- minutes
// of hashing after the last byte, longer than a gateway waits for one request
// -- must not cost the transfer either.
package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// DefaultChunkSize is how much of the stream one PATCH carries. Two chunks are
// buffered in memory, one filling from the source while the other uploads.
const DefaultChunkSize = 256 << 20

// Uploader pushes blobs into one repository.
type Uploader struct {
	// Repository receives the blob.
	Repository name.Repository
	// Transport carries the requests with the repository's credentials (the
	// go-containerregistry transport does the token dance).
	Transport http.RoundTripper
	// ChunkSize is the PATCH size; DefaultChunkSize when zero.
	ChunkSize int
	// Attempts bounds the retries of one chunk; 10 when zero.
	Attempts int
	// Backoff is the first retry's wait, doubling per attempt and capped at a
	// minute; a second when zero.
	Backoff time.Duration
	// RequestTimeout bounds one PATCH; 15 minutes when zero.
	RequestTimeout time.Duration
	// CommitAttempts bounds the PUTs that close the upload; 2 when zero.
	CommitAttempts int
	// CommitTimeout bounds one such PUT; 30 minutes when zero. A gateway in
	// front of the registry usually gives up earlier.
	CommitTimeout time.Duration
	// FinalizeWait is how long, after a commit the registry did not answer
	// with success, the blob is polled for by digest before the commit is
	// tried again; 30 minutes when zero.
	FinalizeWait time.Duration
	// PollInterval is the pause between two of those polls; 30 seconds when zero.
	PollInterval time.Duration
	// Progress, when set, is told the number of bytes the registry has
	// acknowledged so far after every chunk.
	Progress func(uploaded int64)
	// Log, when set, receives one line per commit attempt and poll.
	Log func(format string, args ...any)
}

// Result describes the uploaded blob.
type Result struct {
	Digest v1.Hash
	Size   int64
}

type chunk struct {
	data []byte
	last bool
}

// Upload streams r into a new blob and returns its digest and size. The
// content is hashed as it passes; the registry checks the digest on commit.
func (u *Uploader) Upload(ctx context.Context, r io.Reader) (Result, error) {
	chunkSize := u.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	location, err := u.start(ctx)
	if err != nil {
		return Result{}, err
	}

	hash := sha256.New()
	source := io.TeeReader(r, hash)
	chunks := make(chan chunk)
	free := make(chan []byte, 2)
	free <- make([]byte, chunkSize)
	free <- make([]byte, chunkSize)
	readErr := make(chan error, 1)
	go func() {
		defer close(chunks)
		for {
			var buf []byte
			select {
			case buf = <-free:
			case <-ctx.Done():
				readErr <- ctx.Err()
				return
			}
			n, err := io.ReadFull(source, buf)
			last := err == io.EOF || err == io.ErrUnexpectedEOF
			if err != nil && !last {
				readErr <- err
				return
			}
			select {
			case chunks <- chunk{data: buf[:n], last: last}:
			case <-ctx.Done():
				readErr <- ctx.Err()
				return
			}
			if last {
				readErr <- nil
				return
			}
		}
	}()

	var offset int64
	for c := range chunks {
		if len(c.data) > 0 {
			location, err = u.patch(ctx, location, offset, c.data)
			if err != nil {
				cancel()
				return Result{}, err
			}
			offset += int64(len(c.data))
			if u.Progress != nil {
				u.Progress(offset)
			}
		}
		free <- c.data[:cap(c.data)]
	}
	if err := <-readErr; err != nil {
		return Result{}, fmt.Errorf("reading the blob: %w", err)
	}
	digest := v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(hash.Sum(nil))}
	if err := u.commit(ctx, location, digest, offset); err != nil {
		return Result{}, err
	}
	return Result{Digest: digest, Size: offset}, nil
}

func (u *Uploader) start(ctx context.Context) (*url.URL, error) {
	endpoint := fmt.Sprintf("%s://%s/v2/%s/blobs/uploads/", u.Repository.Scheme(), u.Repository.RegistryStr(), u.Repository.RepositoryStr())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := u.do(req)
	if err != nil {
		return nil, fmt.Errorf("starting the blob upload: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		return nil, responseError("starting the blob upload", resp)
	}
	return u.location(resp)
}

// patch uploads one chunk at offset and returns the location for the next
// one. A failed or partially accepted chunk is resumed from the byte the
// registry reports it holds.
func (u *Uploader) patch(ctx context.Context, location *url.URL, offset int64, data []byte) (*url.URL, error) {
	attempts := u.Attempts
	if attempts <= 0 {
		attempts = 10
	}
	timeout := u.RequestTimeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	end := offset + int64(len(data)) - 1
	from := offset
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			if err := u.wait(ctx, attempt-1); err != nil {
				return nil, err
			}
			held, loc, err := u.status(ctx, location)
			if err != nil {
				lastErr = err
				continue
			}
			location = loc
			switch {
			case held > end+1:
				return nil, fmt.Errorf("the registry holds %d bytes of the upload, more than the %d sent", held, end+1)
			case held == end+1:
				return location, nil
			case held < offset:
				return nil, fmt.Errorf("the registry holds %d bytes of the upload, fewer than the %d it acknowledged", held, offset)
			default:
				from = held
			}
		}
		body := data[from-offset:]
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPatch, location.String(), bytes.NewReader(body))
		if err != nil {
			cancel()
			return nil, err
		}
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Range", fmt.Sprintf("%d-%d", from, end))
		resp, err := u.do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("uploading bytes %d-%d: %w", from, end, err)
			continue
		}
		loc, err := u.location(resp)
		if err == nil && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
			err = responseError(fmt.Sprintf("uploading bytes %d-%d", from, end), resp)
		}
		_ = resp.Body.Close()
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		return loc, nil
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", attempts, lastErr)
}

// status asks the registry how much of the upload it holds.
func (u *Uploader) status(ctx context.Context, location *url.URL) (int64, *url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), http.NoBody)
	if err != nil {
		return 0, nil, err
	}
	resp, err := u.do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("reading the upload's status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusAccepted {
		return 0, nil, responseError("reading the upload's status", resp)
	}
	held, err := parseRange(resp.Header.Get("Range"))
	if err != nil {
		return 0, nil, err
	}
	loc, err := u.location(resp)
	if err != nil {
		loc = location
	}
	return held, loc, nil
}

// commit closes the upload as the blob with the digest. A registry storing a
// blob of tens of gigabytes takes minutes to finalize it after the last byte
// (it hashes what it holds), and a gateway in front of it can give up on the
// request first while the registry keeps working: Azure Container Registry
// answers 504 after eight minutes. So a commit the registry does not confirm
// is followed by polling for the blob by digest, and by another PUT only while
// the upload still exists with every byte. A blob the registry already holds
// under the digest -- a previous run's commit that outlived its 504 -- is
// recognised first; the layer is the same bytes on every build.
func (u *Uploader) commit(ctx context.Context, location *url.URL, digest v1.Hash, size int64) error {
	attempts := u.CommitAttempts
	if attempts <= 0 {
		attempts = 2
	}
	wait := u.FinalizeWait
	if wait <= 0 {
		wait = 30 * time.Minute
	}
	if exists, err := u.blobExists(ctx, digest); err == nil && exists {
		u.logf("the registry already holds %s (%s); the upload is discarded", digest, gib(size))
		u.abandon(ctx, location)
		return nil
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		u.logf("committing %s (%s), attempt %d of %d", digest, gib(size), attempt, attempts)
		err := u.put(ctx, location, digest)
		if err == nil {
			return nil
		}
		// A retried commit can find the upload gone because the first one
		// landed after all; a rejection of the first commit is final.
		if exists, herr := u.blobExists(ctx, digest); herr == nil && exists {
			u.logf("the registry holds %s", digest)
			return nil
		}
		if attempt == 1 && permanent(err) {
			return err
		}
		lastErr = err
		u.logf("%v; polling for the blob for up to %s while the registry finalizes it", err, wait)
		held, err := u.awaitBlob(ctx, digest, wait)
		if err != nil {
			return err
		}
		if held {
			u.logf("the registry holds %s", digest)
			return nil
		}
		stored, loc, err := u.status(ctx, location)
		if err != nil {
			return fmt.Errorf("the blob did not appear after the failed commit (%v), and the upload: %w", lastErr, err)
		}
		if stored != size {
			return fmt.Errorf("the blob did not appear after the failed commit (%v), and the registry holds %d bytes of the upload, not %d", lastErr, stored, size)
		}
		location = loc
	}
	return fmt.Errorf("giving up on the commit after %d attempts: %w", attempts, lastErr)
}

// put is one PUT that closes the upload.
func (u *Uploader) put(ctx context.Context, location *url.URL, digest v1.Hash) error {
	timeout := u.CommitTimeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	q := location.Query()
	q.Set("digest", digest.String())
	final := *location
	final.RawQuery = q.Encode()
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPut, final.String(), http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := u.do(req)
	if err != nil {
		return fmt.Errorf("committing the blob: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusAccepted {
		return responseError("committing the blob", resp)
	}
	return nil
}

// permanent reports an answer to the first commit that no waiting changes: a
// 4xx other than the ones that mean "later".
func permanent(err error) bool {
	var se *StatusError
	if !errors.As(err, &se) {
		return false
	}
	switch se.Status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return false
	}
	return se.Status >= 400 && se.Status < 500
}

// awaitBlob polls for the blob until it is there or the wait is over.
func (u *Uploader) awaitBlob(ctx context.Context, digest v1.Hash, wait time.Duration) (bool, error) {
	interval := u.PollInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(interval):
		}
		exists, err := u.blobExists(ctx, digest)
		switch {
		case err != nil:
			u.logf("asking for %s: %v", digest, err)
		case exists:
			return true, nil
		default:
			u.logf("%s is not there yet, %s left", digest, time.Until(deadline).Round(time.Second))
		}
	}
	return false, nil
}

// blobExists asks the repository for the blob.
func (u *Uploader) blobExists(ctx context.Context, digest v1.Hash) (bool, error) {
	endpoint := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", u.Repository.Scheme(), u.Repository.RegistryStr(), u.Repository.RepositoryStr(), digest)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, http.NoBody)
	if err != nil {
		return false, err
	}
	resp, err := u.do(req)
	if err != nil {
		return false, err
	}
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("the registry answered %d", resp.StatusCode)
}

// abandon cancels an upload the blob makes unnecessary; a registry that has
// already dropped it answers 404, which is fine.
func (u *Uploader) abandon(ctx context.Context, location *url.URL) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, location.String(), http.NoBody)
	if err != nil {
		return
	}
	if resp, err := u.do(req); err == nil {
		_ = resp.Body.Close()
	}
}

func (u *Uploader) logf(format string, args ...any) {
	if u.Log != nil {
		u.Log(format, args...)
	}
}

func gib(n int64) string {
	return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
}

func (u *Uploader) do(req *http.Request) (*http.Response, error) {
	return u.Transport.RoundTrip(req)
}

func (u *Uploader) wait(ctx context.Context, failures int) error {
	backoff := u.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	wait := backoff << (failures - 1)
	if wait > time.Minute {
		wait = time.Minute
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

// location resolves the Location header against the request's URL; the
// registry may answer with a relative path.
func (u *Uploader) location(resp *http.Response) (*url.URL, error) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, errors.New("the registry answered without a Location header")
	}
	return resp.Request.URL.Parse(loc)
}

// parseRange reads the "0-<last>" the registry reports for an upload and
// returns how many bytes it holds.
func parseRange(h string) (int64, error) {
	h = strings.TrimPrefix(strings.TrimSpace(h), "bytes=")
	start, last, ok := strings.Cut(h, "-")
	if !ok || start != "0" {
		return 0, fmt.Errorf("the registry reports an upload range %q", h)
	}
	n, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("the registry reports an upload range %q", h)
	}
	if n == 0 {
		// "0-0" is both "one byte" and the empty upload; no chunk is one byte long.
		return 0, nil
	}
	return n + 1, nil
}

func responseError(what string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return &StatusError{What: what, Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
}

// StatusError is an unexpected registry answer.
type StatusError struct {
	What   string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s: the registry answered %d: %s", e.What, e.Status, e.Body)
}
