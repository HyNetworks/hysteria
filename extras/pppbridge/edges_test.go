package pppbridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The edges: error paths, boundary values and the small pure functions that the
// lifecycle tests never reach because they only ever walk a working session.
//
// Several matter more than their size suggests. A truncated session reason has
// to fail rather than be half-read; a malformed pool CIDR has to be refused at
// startup rather than hand out nonsense addresses; and the sudo command has to
// be assembled correctly on a path no test can execute for real.

// ---------------------------------------------------------------------------
// Errors the caller inspects
// ---------------------------------------------------------------------------

func TestPermanentDialErrorWrapsItsCause(t *testing.T) {
	cause := errors.New("credentials refused")
	e := permanentDialError{err: cause}
	assert.Equal(t, "credentials refused", e.Error())
	assert.Equal(t, cause, e.Unwrap())
	assert.ErrorIs(t, e, cause, "errors.Is must see through it")
}

func TestLinkDownErrorText(t *testing.T) {
	withMsg := &LinkDownError{Reason: SessionReason{Code: ReasonAuthFailed, Message: "bad password"}}
	assert.Equal(t, "ppp: hysteria2 link lost: AUTH_FAILED (bad password)", withMsg.Error())

	bare := &LinkDownError{Reason: SessionReason{Code: ReasonPathNarrowed}}
	assert.Equal(t, "ppp: hysteria2 link lost: PATH_NARROWED", bare.Error(),
		"with nothing to add, the code stands alone rather than trailing empty brackets")

	assert.ErrorIs(t, withMsg, errLinkDown)
}

func TestRelayErrorWrapsItsCause(t *testing.T) {
	cause := errors.New("transport gone")
	e := &relayError{err: cause}
	assert.Equal(t, "transport gone", e.Error())
	assert.ErrorIs(t, e, cause)
}

// ---------------------------------------------------------------------------
// childCommand
// ---------------------------------------------------------------------------

func TestChildCommand(t *testing.T) {
	plain := &Bridge{PPPDPath: "/usr/sbin/pppd", PPPDArgs: []string{"nodetach", "local"}}
	name, args := plain.childCommand()
	assert.Equal(t, "/usr/sbin/pppd", name)
	assert.Equal(t, []string{"nodetach", "local"}, args)

	elevated := &Bridge{PPPDPath: "/usr/sbin/pppd", PPPDArgs: []string{"nodetach"}, Sudo: true}
	name, args = elevated.childCommand()
	assert.Equal(t, "sudo", name)
	assert.Equal(t, []string{"/usr/sbin/pppd", "nodetach"}, args,
		"sudo runs pppd, so pppd's path has to become sudo's first argument")
}

// ---------------------------------------------------------------------------
// startChild and Run
// ---------------------------------------------------------------------------

// NoSpawn with nothing supplied is the pppd pty case: the bridge is pppd's
// child and talks over its own stdio.
func TestStartChildDefaultsToProcessStdio(t *testing.T) {
	b := &Bridge{NoSpawn: true, Logger: zap.NewNop()}
	// cleanup is deliberately not called: it would close this process's stdin.
	r, w, cleanup, wait, err := b.startChild(context.Background())
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	assert.Same(t, os.Stdin, r)
	assert.Same(t, os.Stdout, w)
	assert.NoError(t, wait(), "there is no child to wait for")
}

func TestRunReportsAChildThatCannotStart(t *testing.T) {
	b := &Bridge{PPPDPath: "/nonexistent/pppd", Logger: zap.NewNop()}
	err := b.Run(context.Background(), func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
		t.Error("dial must not be attempted when the child never started")
		return nil, nil, nil, nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start process")
}

// A child that exits without saying anything ends the session quietly: there is
// no link to report as lost because one was never established.
func TestRunReturnsQuietlyWhenTheChildSaysNothing(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	b := &Bridge{PPPDPath: "/bin/sh", PPPDArgs: []string{"-c", "exit 0"}, Logger: zap.NewNop()}
	done := make(chan error, 1)
	go func() {
		done <- b.Run(context.Background(), func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
			t.Error("a child that never spoke must not cause a dial")
			return nil, nil, nil, nil
		})
	}()
	select {
	case err := <-done:
		assert.NoError(t, err, "a child that exits before speaking is not an error")
	case <-time.After(testTimeout):
		t.Fatal("Run did not return for a child that exited immediately")
	}
}

// ---------------------------------------------------------------------------
// Arguments that depend on the session
// ---------------------------------------------------------------------------

// PPPDArgsFn replaces PPPDArgs rather than adding to them. The caller that
// supplies it is the one that owns the whole list -- it built PPPDArgs too, and
// appending would leave two mtu options for pppd to choose between.
func TestChildCommandPrefersTheSessionSizedArguments(t *testing.T) {
	b := &Bridge{
		PPPDPath:   "/usr/sbin/pppd",
		PPPDArgs:   []string{"nodetach", "mtu", "1399"},
		PPPDArgsFn: func() []string { return []string{"nodetach", "mtu", "1378"} },
	}
	name, args := b.childCommand()
	assert.Equal(t, "/usr/sbin/pppd", name)
	assert.Equal(t, []string{"nodetach", "mtu", "1378"}, args)
}

// The ordering is the entire point of PPPDArgsFn. pppd reads mtu and mru once,
// off its command line, so a figure that arrives after it has started can only
// be logged -- which is what used to happen while the far end went on sending
// frames sized to an estimate the transport could not carry.
func TestRunEstablishesTheSessionBeforeAChildWhoseArgumentsDependOnIt(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	pair := newFramePair(4)
	_, server := pair.ends()
	t.Cleanup(pair.shutdown)

	var mu sync.Mutex
	var order []string
	note := func(what string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, what)
	}

	b := &Bridge{
		PPPDPath: "/bin/sh",
		PPPDArgsFn: func() []string {
			note("args")
			return []string{"-c", "exit 0"}
		},
		Logger: zap.NewNop(),
	}

	done := make(chan error, 1)
	go func() {
		done <- b.Run(context.Background(), func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
			note("dial")
			return newDeadControl(), server, func() {}, nil
		})
	}()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Run did not return for a child that exited immediately")
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"dial", "args"}, order,
		"the session must be established before the child's arguments are built")
}

// NoSpawn keeps the old order whatever else is set. pppd is the parent there and
// fixed its MRU before this process existed, so there is nothing a session could
// contribute to its arguments -- and dialling first would only hold a connection
// open waiting on a parent that may never speak.
func TestRunKeepsTheChildFirstInNoSpawn(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })

	dialed := make(chan struct{})
	b := &Bridge{
		NoSpawn:    true,
		In:         pr,
		Out:        nopWriteCloser{io.Discard},
		PPPDArgsFn: func() []string { return []string{"must-not-be-consulted"} },
		Logger:     zap.NewNop(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = b.Run(ctx, func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
			close(dialed)
			return newDeadControl(), nil, func() {}, nil
		})
	}()

	select {
	case <-dialed:
		t.Fatal("NoSpawn must wait for the parent's first frame before dialling")
	case <-time.After(150 * time.Millisecond):
	}
}

// A cancelled context while waiting for the child's first frame returns the
// context's error, not a link failure.
func TestRunHonoursContextCancellationBeforeTheFirstFrame(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })

	b := &Bridge{NoSpawn: true, In: pr, Out: nopWriteCloser{io.Discard}, Logger: zap.NewNop()}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- b.Run(ctx, func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
			t.Error("no dial may happen before the child's first frame")
			return nil, nil, nil, nil
		})
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(testTimeout):
		t.Fatal("Run ignored a cancelled context")
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// ---------------------------------------------------------------------------
// SessionReason on the wire
// ---------------------------------------------------------------------------

func TestReasonCodeStrings(t *testing.T) {
	for code, want := range map[ReasonCode]string{
		ReasonUnknown:         "UNKNOWN",
		ReasonLinkDown:        "LINK_DOWN",
		ReasonAuthFailed:      "AUTH_FAILED",
		ReasonNoRoute:         "NO_ROUTE",
		ReasonNoLNS:           "NO_LNS",
		ReasonLNSUnreachable:  "LNS_UNREACHABLE",
		ReasonLNSDisconnected: "LNS_DISCONNECTED",
		ReasonPathNarrowed:    "PATH_NARROWED",
		ReasonCode(9999):      "UNKNOWN",
	} {
		assert.Equalf(t, want, code.String(), "ReasonCode(%d)", uint64(code))
	}
}

// A peer controls the message, so an over-long one is truncated on the way out
// and refused on the way in. Both halves matter: the writer must not be a way to
// make the reader allocate without bound, and the reader must not trust a length
// it was handed.
func TestSessionReasonBoundsThePeerControlledMessage(t *testing.T) {
	var buf bytes.Buffer
	writeSessionReason(&buf, SessionReason{
		Code:    ReasonLNSDisconnected,
		Message: strings.Repeat("A", maxReasonMessage*3),
	})
	got, err := ReadSessionReason(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	assert.Len(t, got.Message, maxReasonMessage, "the writer truncates")

	// And a hand-built message claiming more than the limit is refused outright.
	var hostile bytes.Buffer
	writeSessionReason(&hostile, SessionReason{Code: ReasonLinkDown, Message: "short"})
	raw := hostile.Bytes()
	// The first three varints are code/result/error, so the fourth byte is the
	// message length here; rewrite it to a two-byte varint past the cap.
	raw[3], raw[4] = 0x80|0x0F, 0xFF
	_, err = ReadSessionReason(bytes.NewReader(raw))
	assert.Error(t, err, "a length past the cap must be refused, not allocated")
}

// Every prefix of a valid reason must fail rather than yield a half-read one: a
// caller that acted on a partially decoded reason could block a working
// interface on a code that was never sent.
func TestReadSessionReasonRejectsEveryTruncation(t *testing.T) {
	var buf bytes.Buffer
	writeSessionReason(&buf, SessionReason{
		Code: ReasonLNSDisconnected, Result: 2, Error: 6, Message: "cleared",
	})
	full := buf.Bytes()
	for n := 0; n < len(full); n++ {
		_, err := ReadSessionReason(bytes.NewReader(full[:n]))
		assert.Errorf(t, err, "a %d-byte prefix of a %d-byte reason must not decode", n, len(full))
	}
	got, err := ReadSessionReason(bytes.NewReader(full))
	require.NoError(t, err)
	assert.Equal(t, "cleared", got.Message)
}

// ---------------------------------------------------------------------------
// Small pure functions
// ---------------------------------------------------------------------------

// PPP protocol field compression: an odd first octet means a one-byte protocol
// number (RFC 1661 s6.5). pppd negotiates it, so frames really arrive this way.
func TestParsePPPFrameHandlesProtocolFieldCompression(t *testing.T) {
	proto, payload := parsePPPFrame([]byte{0xFF, 0x03, 0x21, 0xDE, 0xAD})
	assert.Equal(t, uint16(0x21), proto)
	assert.Equal(t, []byte{0xDE, 0xAD}, payload)

	proto, payload = parsePPPFrame([]byte{0x21, 0xBE})
	assert.Equal(t, uint16(0x21), proto)
	assert.Equal(t, []byte{0xBE}, payload)
}

func TestIPPoolRejectsANonIPv4CIDR(t *testing.T) {
	_, err := NewIPPool("2001:db8::/64")
	assert.Error(t, err, "an IPv6 prefix is not an IPv4 pool")

	p, err := NewIPPool("10.0.0.0/24")
	require.NoError(t, err)
	// Releasing something that was never an address must not corrupt the pool.
	p.Release("not-an-ip")
	ip, err := p.Allocate()
	require.NoError(t, err)
	assert.NotEmpty(t, ip)
}

func TestDecodeHDLCRejectsABufferWithNoFrames(t *testing.T) {
	_, err := DecodeHDLC(nil)
	assert.Error(t, err, "an empty buffer contains no frame")
}
