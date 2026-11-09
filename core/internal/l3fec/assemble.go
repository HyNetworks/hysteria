package l3fec

import (
	"sync"
	"time"
)

// holdFor is how long an incomplete group may block later groups.
// QUIC retransmits a missing chunk in about one RTT. Past this, the group
// is unrecoverable and must be skipped so it does not stall the path.
const holdFor = 400 * time.Millisecond

// Counts is how downlink groups were finished or abandoned.
// Direct means every data chunk arrived. Repaired means parity filled gaps.
// Skip is a group given up after holdFor. Late is a chunk for an already
// finished or skipped group.
type Counts struct {
	Direct   uint64
	Repaired uint64
	Skip     uint64
	Late     uint64
}

// Assembler restores downlink IP packets and emits them in group order.
// Chunks of one group travel on independent streams. Any k of them rebuild
// the group, so a lost chunk does not wait for QUIC retransmission.
type Assembler struct {
	mu      sync.Mutex
	next    uint32
	hold    map[uint32]*grp
	out     chan []byte
	counts  Counts
	holdFor time.Duration
}

type grp struct {
	k, r int
	data map[int][]byte
	par  map[int][]byte
	at   time.Time
}

// NewAssembler sends recovered packets on out, in order.
func NewAssembler(out chan []byte) *Assembler {
	return &Assembler{
		hold:    make(map[uint32]*grp),
		out:     out,
		holdFor: holdFor,
	}
}

// SetHold is how long an incomplete group may block later groups.
// The floor matches one retransmission on the path this was tuned for.
func (a *Assembler) SetHold(d time.Duration) {
	if d < holdFor {
		d = holdFor
	}
	if d > 1500*time.Millisecond {
		d = 1500 * time.Millisecond
	}
	a.mu.Lock()
	a.holdFor = d
	a.mu.Unlock()
}

// Hold returns the current incomplete-group wait.
func (a *Assembler) Hold() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.holdFor
}

// Push adds one encoded blob. Recovered packets are sent on out.
func (a *Assembler) Push(blob []byte, now time.Time) {
	c, ok := Unpack(blob)
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if c.Group < a.next {
		a.counts.Late++
		return
	}
	g := a.hold[c.Group]
	if g == nil {
		g = &grp{
			k:    c.K,
			r:    c.R,
			data: make(map[int][]byte),
			par:  make(map[int][]byte),
			at:   now,
		}
		a.hold[c.Group] = g
	}
	if c.K != g.k || c.R != g.r {
		return
	}
	if c.Index < g.k {
		if _, exists := g.data[c.Index]; !exists {
			g.data[c.Index] = append([]byte(nil), c.Payload...)
		}
	} else if _, exists := g.par[c.Index-g.k]; !exists {
		g.par[c.Index-g.k] = append([]byte(nil), c.Payload...)
	}
	a.emit(now)
}

// Tick skips a group that has been incomplete for too long.
func (a *Assembler) Tick(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.emit(now)
}

func (a *Assembler) emit(now time.Time) {
	for {
		g := a.hold[a.next]
		if g == nil {
			if !a.shouldSkip(now) {
				return
			}
			a.counts.Skip++
			a.next++
			continue
		}
		repaired := len(g.data) != g.k
		pkts, ok := g.finish()
		if !ok {
			if now.Sub(g.at) <= a.holdFor {
				return
			}
			a.counts.Skip++
			delete(a.hold, a.next)
			a.next++
			continue
		}
		if repaired {
			a.counts.Repaired++
		} else {
			a.counts.Direct++
		}
		for _, p := range pkts {
			a.out <- p
		}
		delete(a.hold, a.next)
		a.next++
	}
}

// Counts returns a snapshot of group outcomes since the assembler opened.
func (a *Assembler) Counts() Counts {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.counts
}

func (a *Assembler) shouldSkip(now time.Time) bool {
	var oldest time.Time
	for id, g := range a.hold {
		if id <= a.next {
			continue
		}
		if oldest.IsZero() || g.at.Before(oldest) {
			oldest = g.at
		}
	}
	return !oldest.IsZero() && now.Sub(oldest) > a.holdFor
}

func (g *grp) finish() ([][]byte, bool) {
	if g.k <= 0 {
		return nil, false
	}
	if len(g.data) == g.k {
		out := make([][]byte, g.k)
		for i := 0; i < g.k; i++ {
			p := g.data[i]
			if p == nil {
				return nil, false
			}
			out[i] = p
		}
		return out, true
	}
	if len(g.par) == 0 || len(g.data)+len(g.par) < g.k {
		return nil, false
	}
	return Recover(g.k, g.data, g.par)
}
