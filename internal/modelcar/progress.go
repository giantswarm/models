package modelcar

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// progress reports the transfer every interval: CircleCI ends a step that is
// silent for too long, and a build of a 100 GiB model is silent for an hour
// otherwise.
type progress struct {
	total      int64
	downloaded atomic.Int64
	uploaded   atomic.Int64
	started    time.Time
	log        func(string, ...any)
}

func (p *progress) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.report()
		}
	}
}

func (p *progress) report() {
	elapsed := time.Since(p.started)
	down, up := p.downloaded.Load(), p.uploaded.Load()
	rate := float64(up) / elapsed.Seconds()
	eta := "-"
	if rate > 0 && up < p.total {
		eta = (time.Duration(float64(p.total-up)/rate) * time.Second).Round(time.Minute).String()
	}
	p.log("downloaded %s, uploaded %s of %s (%.0f%%) at %s/s after %s, ETA %s",
		humanBytes(down), humanBytes(up), humanBytes(p.total), 100*float64(up)/float64(max(p.total, 1)),
		humanBytes(int64(rate)), elapsed.Round(time.Second), eta)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
