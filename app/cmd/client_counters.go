package cmd

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/extras/v2/pppbridge"
)

// pppBytesEnv names a file where this link publishes what it has carried.
//
// Per slot, like the state and MTU files beside it, and for the same reason: a
// bundle has one of these questions per link. It is the only answer available.
// The kernel counts bytes on the bundle unit and keeps nothing at all on a
// member channel, so the sum of these files is the only way to say which server
// is carrying which share -- and, more usefully, to say that a link reporting
// "join unconfirmed" is demonstrably carrying traffic anyway.
const pppBytesEnv = "HYSTERIA_PPP_BYTES"

const (
	// How often the counters are read. One second because the figure this feeds
	// is a rate rather than a total, and a graph drawn from five-second samples
	// cannot show a stall that lasts four.
	pppSampleInterval = time.Second

	// How often the file is replaced. Three samples per write rather than one,
	// because the reader polls no faster than this and each write is a create and
	// a rename on tmpfs; the history below means nothing is lost by batching.
	pppWriteInterval = 3 * time.Second

	// How many samples the published history holds. Sixty one-second samples is
	// the same minute LuCI's own realtime graphs show, which is what the page
	// rendering this is drawn to match.
	pppHistorySamples = 60
)

// pppCounterPublisher samples a link's counters and publishes them, with a short
// history, where the OpenWrt status collector reads them back.
//
// The history is the part worth explaining. A cumulative total alone would make
// the page derive its own rates from successive polls, and it cannot do that
// honestly: the browser has no reliable clock against the router's, two
// independent five-second polls run on that page, and a reload throws away
// everything. Publishing the deltas this process measured means the rate is
// computed once, here, against the monotonic clock of the machine that took the
// samples -- and a page opened thirty seconds into a link's life still draws
// thirty seconds of graph.
type pppCounterPublisher struct {
	path     string
	counters *pppbridge.Counters

	// The schedule, as fields rather than the constants directly, so a test can
	// exercise a full window in milliseconds instead of the minute the real one
	// takes. The Bridge's probe timings are overridable for the same reason.
	sampleInterval time.Duration
	writeInterval  time.Duration
	historyMax     int

	// started says whether loop is actually running.
	//
	// Not a formality: start is called from OnSessionUp and stop unconditionally
	// after Serve returns, so a link whose server was never reachable reaches stop
	// having never started. Without this, the wait below would block forever on a
	// goroutine that does not exist -- and it would do so on the failure path,
	// where the process is trying to exit so netifd can redial.
	started  atomic.Bool
	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

func newPPPCounterPublisher(c *pppbridge.Counters) *pppCounterPublisher {
	return &pppCounterPublisher{
		path:           os.Getenv(pppBytesEnv),
		counters:       c,
		sampleInterval: pppSampleInterval,
		writeInterval:  pppWriteInterval,
		historyMax:     pppHistorySamples,
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}
}

// start begins sampling, and does nothing at all when there is nowhere to
// publish to. That is the ordinary case off OpenWrt: nothing sets the variable,
// so a plain client run costs neither the goroutine nor the timer.
func (p *pppCounterPublisher) start() {
	if p == nil || p.path == "" || p.counters == nil {
		return
	}
	if !p.started.CompareAndSwap(false, true) {
		return
	}
	// Written here, synchronously, before the goroutine exists and before the
	// caller goes on to announce that this link is up.
	//
	// The file outlives the session that wrote it: the shell sweeps it at the next
	// bring-up rather than when a link drops, so at this moment the path may still
	// hold the previous session's totals. The collector will not show them -- it
	// gates the figures on this link reporting up -- but the caller is about to
	// report exactly that, and the first scheduled write is three seconds away. So
	// the stale reading is replaced with this session's zeroes first, and the
	// window in which the two disagree does not exist.
	p.publish(p.counters.Read(), nil, 0)
	go p.loop()
}

// stop flushes a final reading and waits for the goroutine to finish.
//
// The flush matters more than it looks. A link that fails is exactly the one an
// operator goes looking at, and without it the last figure on the page would be
// up to three seconds stale in the one direction that misleads -- showing
// traffic still flowing on a link that had already stopped.
func (p *pppCounterPublisher) stop() {
	if p == nil || !p.started.Load() {
		return
	}
	p.stopOnce.Do(func() { close(p.stopCh) })
	<-p.doneCh
}

func (p *pppCounterPublisher) loop() {
	defer close(p.doneCh)

	sample := time.NewTicker(p.sampleInterval)
	defer sample.Stop()
	write := time.NewTicker(p.writeInterval)
	defer write.Stop()

	started := time.Now()
	prev := p.counters.Read()
	hist := make([]pppSample, 0, p.historyMax)

	for {
		select {
		case <-sample.C:
			cur := p.counters.Read()
			hist = appendPPPSample(hist, p.historyMax, pppSample{
				rx: cur.RxBytes - prev.RxBytes,
				tx: cur.TxBytes - prev.TxBytes,
			})
			prev = cur
		case <-write.C:
			// A fresh read rather than prev, so the cumulative figures on the page
			// are current to the write rather than to the last sample tick. The
			// history stays as sampled: it is a rate series, and stretching its
			// last bucket to cover a partial interval would overstate it.
			p.publish(p.counters.Read(), hist, time.Since(started))
		case <-p.stopCh:
			// Read again rather than reusing prev: up to a second of traffic has
			// gone by since the last sample, and this is the reading that stays on
			// the page until the link comes back.
			p.publish(p.counters.Read(), hist, time.Since(started))
			return
		}
	}
}

// pppSample is one interval's worth of traffic, in bytes each way.
type pppSample struct{ rx, tx uint64 }

// appendPPPSample adds a sample, dropping the oldest once the window is full.
func appendPPPSample(hist []pppSample, max int, s pppSample) []pppSample {
	if len(hist) < max {
		return append(hist, s)
	}
	return append(hist[1:], s)
}

// publish replaces the file with the current reading.
//
// pid is written so a reading can be traced back to the process that took it,
// which is the only handle anything reading a log afterwards has on one link of a
// bundle. It is deliberately not what the collector gates staleness on: for a
// member link the slot's claim names pppd rather than this process, so a pid
// comparison there would reject every reading a member ever published. The
// collector clears this file with the rest of the slot's session state instead.
func (p *pppCounterPublisher) publish(s pppbridge.Snapshot, hist []pppSample, uptime time.Duration) {
	var b strings.Builder

	b.WriteString("pid=" + strconv.Itoa(os.Getpid()) + "\n")
	b.WriteString("rx=" + strconv.FormatUint(s.RxBytes, 10) + "\n")
	b.WriteString("tx=" + strconv.FormatUint(s.TxBytes, 10) + "\n")
	b.WriteString("rxpkts=" + strconv.FormatUint(s.RxFrames, 10) + "\n")
	b.WriteString("txpkts=" + strconv.FormatUint(s.TxFrames, 10) + "\n")
	b.WriteString("for=" + strconv.Itoa(int(uptime/time.Second)) + "\n")
	b.WriteString("histstep=" + strconv.FormatInt(p.sampleInterval.Milliseconds(), 10) + "\n")
	b.WriteString("hist=" + encodePPPHistory(hist) + "\n")

	writeFileAtomically(p.path, b.String())
}

// histstep is published in milliseconds rather than seconds so that the value
// stays exact for any schedule: the tests run this loop far faster than once a
// second, and a whole-second field would round their step to zero -- which the
// page would then divide a rate by.

// encodePPPHistory renders the window as one line, oldest sample first.
//
// One line of "rx:tx" pairs rather than anything structured, because the reader
// on the other side is a POSIX shell that passes the value through into JSON
// without looking at it. The format is this package's own on both sides, which
// is what makes reading it back with sed acceptable there and would not
// anywhere else.
func encodePPPHistory(hist []pppSample) string {
	var b strings.Builder
	for i, s := range hist {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(s.rx, 10))
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(s.tx, 10))
	}
	return b.String()
}
