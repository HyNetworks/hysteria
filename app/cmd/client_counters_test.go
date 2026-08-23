package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/apernet/hysteria/extras/v2/pppbridge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readKV parses the key=value file the publisher writes, which is the same
// format the OpenWrt collector reads a line at a time.
func readKV(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)

	rv := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			rv[k] = v
		}
	}
	return rv
}

// newTestPublisher builds one on a fast schedule against a scratch file.
func newTestPublisher(t *testing.T, c *pppbridge.Counters) (*pppCounterPublisher, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "bytes")
	t.Setenv(pppBytesEnv, path)

	p := newPPPCounterPublisher(c)
	p.sampleInterval = 5 * time.Millisecond
	p.writeInterval = 15 * time.Millisecond
	p.historyMax = 4
	return p, path
}

// The headline case: what the counters hold reaches the file.
func TestCounterPublisherWritesTotals(t *testing.T) {
	c := new(pppbridge.Counters)
	p, path := newTestPublisher(t, c)

	c.RxBytes.Store(4096)
	c.RxFrames.Store(12)
	c.TxBytes.Store(1024)
	c.TxFrames.Store(5)

	p.start()
	p.stop()

	kv := readKV(t, path)
	assert.Equal(t, "4096", kv["rx"])
	assert.Equal(t, "12", kv["rxpkts"])
	assert.Equal(t, "1024", kv["tx"])
	assert.Equal(t, "5", kv["txpkts"])
	assert.Equal(t, strconv.Itoa(os.Getpid()), kv["pid"], "the reading names the process it describes")
	assert.Equal(t, "5", kv["histstep"], "the step is published in milliseconds")
}

// stop must leave a final reading behind, because a link that has just failed is
// the one somebody is looking at, and the alternative is a page showing traffic
// on a link that stopped seconds ago.
func TestCounterPublisherFlushesOnStop(t *testing.T) {
	c := new(pppbridge.Counters)
	p, path := newTestPublisher(t, c)
	p.writeInterval = time.Hour // nothing but the flush can write

	p.start()
	c.RxBytes.Store(777)
	p.stop()

	assert.Equal(t, "777", readKV(t, path)["rx"])
}

// The history is a window, not a log: once it is full the oldest sample goes.
func TestCounterPublisherHistoryIsBounded(t *testing.T) {
	c := new(pppbridge.Counters)
	p, path := newTestPublisher(t, c)

	p.start()
	// Long enough for many more than historyMax samples to have been taken.
	time.Sleep(150 * time.Millisecond)
	p.stop()

	hist := readKV(t, path)["hist"]
	require.NotEmpty(t, hist)
	assert.LessOrEqual(t, len(strings.Split(hist, ",")), p.historyMax,
		"the window must not grow without bound")
}

// Each history entry is that interval's traffic, not a running total. A page
// drawing a rate from these must not have to difference them again.
func TestCounterPublisherHistoryHoldsDeltas(t *testing.T) {
	c := new(pppbridge.Counters)
	p, path := newTestPublisher(t, c)
	p.sampleInterval = 20 * time.Millisecond
	p.writeInterval = time.Hour

	p.start()

	// Two intervals with a known amount of traffic in each, spaced so that a
	// sample tick falls between them.
	time.Sleep(10 * time.Millisecond)
	c.RxBytes.Add(100)
	time.Sleep(20 * time.Millisecond)
	c.RxBytes.Add(300)
	time.Sleep(20 * time.Millisecond)

	p.stop()

	hist := strings.Split(readKV(t, path)["hist"], ",")
	require.GreaterOrEqual(t, len(hist), 2)

	// Deltas, so the two buckets carry 100 and 300 rather than 100 and 400.
	// Asserted as a set rather than by position: the sleeps above order the
	// traffic against the ticks, not the ticks against each other.
	var seen []string
	for _, h := range hist {
		rx, _, ok := strings.Cut(h, ":")
		require.True(t, ok, "each entry is rx:tx")
		if rx != "0" {
			seen = append(seen, rx)
		}
	}
	assert.Equal(t, []string{"100", "300"}, seen,
		"each bucket holds its own interval's bytes, not a running total")
}

// With nowhere to publish to, the publisher does nothing at all -- no goroutine,
// no timer, no file. That is every run of this binary that is not a link in an
// OpenWrt bundle.
func TestCounterPublisherIsInertWithoutTheEnvVar(t *testing.T) {
	t.Setenv(pppBytesEnv, "")

	c := new(pppbridge.Counters)
	p := newPPPCounterPublisher(c)

	p.start()
	p.stop() // must not block on a goroutine that was never started
}

// stop is safe to call twice, and safe to call without start. The nospawn path
// calls it on every exit path, including ones where the session never came up.
func TestCounterPublisherStopIsIdempotent(t *testing.T) {
	c := new(pppbridge.Counters)
	p, _ := newTestPublisher(t, c)

	p.start()
	p.stop()
	p.stop()
}

// A publisher whose session never came up never started, so stopping it must not
// wait for a goroutine that does not exist.
func TestCounterPublisherStopWithoutStart(t *testing.T) {
	c := new(pppbridge.Counters)
	p, path := newTestPublisher(t, c)

	done := make(chan struct{})
	go func() {
		p.stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop blocked on a goroutine that was never started")
	}

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "a link that never came up publishes no figures")
}

func TestAppendPPPSampleDropsOldest(t *testing.T) {
	var hist []pppSample
	for i := 1; i <= 5; i++ {
		hist = appendPPPSample(hist, 3, pppSample{rx: uint64(i)})
	}

	require.Len(t, hist, 3)
	assert.Equal(t, uint64(3), hist[0].rx, "the oldest two were dropped")
	assert.Equal(t, uint64(5), hist[2].rx, "and the newest is last")
}

func TestEncodePPPHistory(t *testing.T) {
	assert.Empty(t, encodePPPHistory(nil), "an empty window encodes to nothing")
	assert.Equal(t, "1:2", encodePPPHistory([]pppSample{{rx: 1, tx: 2}}))
	assert.Equal(t, "1:2,30:40", encodePPPHistory([]pppSample{{rx: 1, tx: 2}, {rx: 30, tx: 40}}))
}
