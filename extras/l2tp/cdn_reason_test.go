package l2tp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The Result Code AVP is the only thing in a CDN that says *why* the LNS hung
// up, and the LAC's whole reason-propagation path -- Session.CloseReason, the
// SessionReason it puts on the control stream, whether the client is told to
// retry -- is downstream of it. These tests drive the value in over the wire
// (RFC 2661 s4.4.2: result(2) + error(2) + optional message, every part after
// the first two octets optional) and then straight through parseResultCode.

// ---------------------------------------------------------------------------
// handleCDN -> Session.CloseReason
// ---------------------------------------------------------------------------

// buildCDNWithResultCodeValue assembles a CDN whose Result Code AVP carries an
// arbitrary value, which BuildCDN cannot do: it always emits the full four
// octets. A nil value omits the AVP entirely.
func buildCDNWithResultCodeValue(sessionID uint16, value []byte) []byte {
	buf := EncodeUint16AVP(AVPMessageType, MsgTypeCDN)
	buf = append(buf, EncodeUint16AVP(AVPAssignedSessionID, sessionID)...)
	if value != nil {
		buf = append(buf, EncodeAVP(AVPResultCode, value)...)
	}
	return buf
}

// resultCodeValue lays out a well-formed Result Code value.
func resultCodeValue(result, errCode uint16, msg string) []byte {
	v := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint16(v[0:2], result)
	binary.BigEndian.PutUint16(v[2:4], errCode)
	copy(v[4:], msg)
	return v
}

func TestCDNRecordsItsResultCodeOnTheSession(t *testing.T) {
	tests := []struct {
		name       string
		value      []byte
		wantResult uint16
		wantError  uint16
		wantMsg    string
	}{
		{
			name:  "no Result Code AVP at all reports zeroes",
			value: nil,
		},
		{
			name:  "a Result Code AVP with an empty value reports zeroes",
			value: []byte{},
		},
		{
			name:  "a single octet is too short to be a result",
			value: []byte{0x03},
		},
		{
			name:       "two octets carry the result only",
			value:      []byte{0x00, 0x03},
			wantResult: 3,
		},
		{
			name:       "three octets keep the result and drop the half error",
			value:      []byte{0x00, 0x03, 0x00},
			wantResult: 3,
		},
		{
			name:       "four octets carry result and error",
			value:      []byte{0x00, 0x02, 0x00, 0x06},
			wantResult: 2,
			wantError:  6,
		},
		{
			name:       "a trailing message is kept alongside both codes",
			value:      resultCodeValue(2, 6, "no such user"),
			wantResult: 2,
			wantError:  6,
			wantMsg:    "no such user",
		},
		{
			name:       "a message with no error code is still a message",
			value:      resultCodeValue(3, 0, "administrative"),
			wantResult: 3,
			wantMsg:    "administrative",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tun, f := establishTunnel(t, 0)
			s := establishSession(t, tun, f)

			f.send(uint16(tun.ns.Load()), s.localSessionID,
				buildCDNWithResultCodeValue(s.remoteSID(), tt.value))

			requireSessionGone(t, tun, s, 0)

			result, errCode, msg := s.CloseReason()
			assert.Equal(t, tt.wantResult, result)
			assert.Equal(t, tt.wantError, errCode)
			assert.Equal(t, tt.wantMsg, msg)

			assert.True(t, tun.Alive(), "a CDN never takes the tunnel with it")
		})
	}
}

// A CDN naming a session this LAC does not have is the ordinary consequence of
// a race (the LAC tore the call down first) or of a confused peer. It must be
// dropped quietly: no panic, and above all no collateral damage to the sessions
// that are still up.
func TestCDNForAnUnknownSessionLeavesLiveSessionsAlone(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)
	require.Equal(t, lnsSessionID, s.remoteSID())

	strangers := []struct {
		name string
		sid  uint16
	}{
		{"one past the live session", lnsSessionID + 1},
		{"session zero", 0},
		{"the largest session ID there is", 0xFFFF},
		// s.localSessionID is deliberately absent: it is a valid local addressee,
		// and a CDN carrying it in the header now closes that session (RFC 2661
		// s3.1). See "CDN is resolved by the header Session field" in
		// tunnel_conformance_test.go.
	}
	for _, tt := range strangers {
		t.Run(tt.name, func(t *testing.T) {
			require.NotEqual(t, s.remoteSID(), tt.sid)

			f.send(uint16(tun.ns.Load()), tt.sid,
				BuildCDN(tt.sid, 2, 6, "gone"))

			ack := f.mustNextPacket()
			require.True(t, ack.zlb, "the CDN is still acknowledged, got %x", ack.raw)

			// handleControl acks before it dispatches, so the ZLB above says
			// nothing about whether handleCDN has run yet. Without this barrier
			// every assertion below could be reading the state from before the
			// CDN was ever looked at, and would pass even if the CDN did close
			// the wrong session a moment later.
			f.barrier(tun)

			assert.False(t, sessionIsClosed(s), "the live session is untouched")
			assert.Equal(t, 1, tun.SessionCount())
			assert.True(t, tun.Alive())

			result, errCode, msg := s.CloseReason()
			assert.Zero(t, result, "another session's reason must not be recorded here")
			assert.Zero(t, errCode)
			assert.Empty(t, msg)
		})
	}

	// And the real thing still works afterwards.
	f.send(uint16(tun.ns.Load()), s.localSessionID, BuildCDN(s.remoteSID(), 3, 0, "cleared"))
	requireSessionGone(t, tun, s, 0)
	result, _, msg := s.CloseReason()
	assert.Equal(t, uint16(3), result)
	assert.Equal(t, "cleared", msg)
}

// KNOWN DATA RACE, not fixed here because it is in production code.
//
// handleCDN now finds its target by scanning t.sessions and comparing
// s.remoteSID() (tunnel.go). That field is written by Session.establish
// (session.go, on the goroutine inside CreateSession) with no lock at all,
// while handleCDN reads it on recvLoop's goroutine under t.mu. The mutex only
// guards the map, not the field, so the two are unsynchronised.
//
// It is reachable whenever a CDN arrives on a tunnel that has another call
// mid-setup -- routine on a LAC with more than one call per LNS -- and the
// scan touches *every* session, so the CDN does not have to concern the one
// being established. The predecessor of this code looked the session up in the
// map by key and never read a Session field, so the refactor introduced it.
//
// This reproducer is left runnable but off by default: it fails under -race,
// which is the point, and the package has to stay green. Run it with
//
//	L2TP_RACE_REPRO=1 go test ./l2tp/ -run TestHandleCDNRacesSessionEstablish -race
//
// and delete the gate once tunnel.go stops reading remoteSessionID unguarded.
func TestHandleCDNRacesSessionEstablish(t *testing.T) {
	if os.Getenv("L2TP_RACE_REPRO") == "" {
		t.Skip("reproduces a live data race in handleCDN; set L2TP_RACE_REPRO=1 to run it")
	}
	for i := 0; i < 20; i++ {
		tun, f := establishTunnel(t, 0)

		resCh := make(chan *Session, 1)
		go func() {
			s, err := tun.CreateSession(testSubscriber, "5551234")
			assert.NoError(t, err)
			resCh <- s
		}()

		icrq := f.mustNextControl(MsgTypeICRQ)
		sidAVP := FindAVP(icrq.avps, 0, AVPAssignedSessionID)
		require.NotNil(t, sidAVP)
		localSID, err := AVPUint16(sidAVP)
		require.NoError(t, err)

		// The ICRP is what unblocks establish() to write remoteSessionID. The
		// CDNs right behind it keep recvLoop scanning the session set while it
		// does. They name a session nobody has, so nothing is closed: the race
		// is on the read, not on the outcome.
		f.send(icrq.hdr.Ns+1, localSID, buildICRP(lnsSessionID))
		for range 8 {
			f.send(uint16(tun.ns.Load()), localSID, BuildCDN(0x7777, 2, 6, "nobody"))
		}

		iccn := f.mustNextControl(MsgTypeICCN)
		f.sendZLB(iccn.hdr.Ns + 1)
		select {
		case <-resCh:
		case <-time.After(waitFor):
			t.Fatal("CreateSession did not return")
		}
		tun.Close()
	}
}

// ---------------------------------------------------------------------------
// parseResultCode
// ---------------------------------------------------------------------------

func TestParseResultCode(t *testing.T) {
	tests := []struct {
		name       string
		avps       []AVP
		wantResult uint16
		wantError  uint16
		wantMsg    string
	}{
		{
			name: "no AVPs at all",
			avps: nil,
		},
		{
			name: "no Result Code AVP among the ones present",
			avps: []AVP{
				{Type: AVPMessageType, Value: []byte{0x00, 0x0E}},
				{Type: AVPAssignedSessionID, Value: []byte{0x42, 0x42}},
			},
		},
		{
			name: "nil value",
			avps: []AVP{{Type: AVPResultCode}},
		},
		{
			name: "empty value",
			avps: []AVP{{Type: AVPResultCode, Value: []byte{}}},
		},
		{
			name: "one octet: too short for a result",
			avps: []AVP{{Type: AVPResultCode, Value: []byte{0xFF}}},
		},
		{
			name:       "two octets: result only",
			avps:       []AVP{{Type: AVPResultCode, Value: []byte{0x01, 0x02}}},
			wantResult: 0x0102,
		},
		{
			name:       "three octets: the truncated error code is discarded",
			avps:       []AVP{{Type: AVPResultCode, Value: []byte{0x00, 0x02, 0xFF}}},
			wantResult: 2,
		},
		{
			name:       "four octets: result and error",
			avps:       []AVP{{Type: AVPResultCode, Value: []byte{0x00, 0x02, 0x00, 0x06}}},
			wantResult: 2,
			wantError:  6,
		},
		{
			name:       "five octets: a one-character message",
			avps:       []AVP{{Type: AVPResultCode, Value: []byte{0x00, 0x02, 0x00, 0x06, 'x'}}},
			wantResult: 2,
			wantError:  6,
			wantMsg:    "x",
		},
		{
			name:       "the maximum codes are not special",
			avps:       []AVP{{Type: AVPResultCode, Value: []byte{0xFF, 0xFF, 0xFF, 0xFF}}},
			wantResult: 0xFFFF,
			wantError:  0xFFFF,
		},
		{
			name: "a vendor-specific Result Code is not the IETF one",
			avps: []AVP{{VendorID: 9, Type: AVPResultCode, Value: []byte{0x00, 0x02, 0x00, 0x06}}},
		},
		{
			name: "the first IETF Result Code wins over any later one",
			avps: []AVP{
				{VendorID: 9, Type: AVPResultCode, Value: []byte{0x00, 0x09}},
				{Type: AVPResultCode, Value: []byte{0x00, 0x02}},
				{Type: AVPResultCode, Value: []byte{0x00, 0x03}},
			},
			wantResult: 2,
		},
		{
			name:       "an embedded NUL becomes a space rather than terminating the message",
			avps:       []AVP{{Type: AVPResultCode, Value: []byte{0x00, 0x02, 0x00, 0x06, 'a', 0x00, 'b'}}},
			wantResult: 2,
			wantError:  6,
			wantMsg:    "a b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, errCode, msg := parseResultCode(tt.avps)
			assert.Equal(t, tt.wantResult, result)
			assert.Equal(t, tt.wantError, errCode)
			assert.Equal(t, tt.wantMsg, msg)
		})
	}
}

// Oversized messages are capped rather than kept whole; see the "length is
// capped" case of TestParseResultCodeSanitisesTheMessage.

// The Result Code message is peer-controlled and ends up in log lines and in the
// SessionReason sent to the client, so it is bounded and sanitised: invalid UTF-8
// and control characters become spaces, and the length is capped.
func TestParseResultCodeSanitisesTheMessage(t *testing.T) {
	build := func(msg []byte) []AVP {
		v := append([]byte{0, 2, 0, 6}, msg...)
		return []AVP{{VendorID: 0, Type: AVPResultCode, Value: v}}
	}

	t.Run("control characters are replaced", func(t *testing.T) {
		_, _, msg := parseResultCode(build([]byte("bad\x00pass\nword")))
		assert.NotContains(t, msg, "\x00")
		assert.NotContains(t, msg, "\n", "a newline would corrupt a log line")
		assert.Contains(t, msg, "bad")
		assert.Contains(t, msg, "word")
	})

	t.Run("invalid UTF-8 is replaced", func(t *testing.T) {
		_, _, msg := parseResultCode(build([]byte{0xFF, 0xFE, 'o', 'k'}))
		assert.True(t, utf8.ValidString(msg), "what we forward must be valid UTF-8")
		assert.Contains(t, msg, "ok")
	})

	t.Run("length is capped", func(t *testing.T) {
		_, _, msg := parseResultCode(build(bytes.Repeat([]byte("A"), 4000)))
		assert.LessOrEqual(t, len(msg), maxResultMessage)
	})

	t.Run("a well-formed message is preserved", func(t *testing.T) {
		_, _, msg := parseResultCode(build([]byte("no such user")))
		assert.Equal(t, "no such user", msg)
	})
}

// ---------------------------------------------------------------------------
// Close reasons
// ---------------------------------------------------------------------------

// testSession is a bare Session for the tests that only exercise its reason
// bookkeeping and need no tunnel behind it.
func testSession(t *testing.T) *Session {
	t.Helper()
	return &Session{
		logger:         zap.NewNop(),
		localSessionID: 1,
		subscriber:     "alice",
		recvCh:         make(chan []byte, 8),
		closed:         make(chan struct{}),
	}
}

// The handler reads CloseReason the instant the session closes, so the two must
// not race: handleCDN records the reason before it closes the session, and
// closing the session is what wakes the reader. A reason recorded a moment later
// is a reason the client never hears.
func TestTheCloseReasonIsAlreadyThereWhenTheSessionCloses(t *testing.T) {
	type outcome struct {
		endedByLNS bool
		result     uint16
		errCode    uint16
		msg        string
	}
	// Repeated because this is an ordering property between two goroutines:
	// one run proves little.
	for i := 0; i < 25; i++ {
		tun, f := establishTunnel(t, 0)
		s := establishSession(t, tun, f)

		outCh := make(chan outcome, 1)
		go func() {
			<-s.closed
			result, errCode, msg := s.CloseReason()
			outCh <- outcome{s.EndedByLNS(), result, errCode, msg}
		}()

		f.send(uint16(tun.ns.Load()), s.localSessionID,
			BuildCDN(s.remoteSID(), 2, 6, "call cleared"))

		select {
		case got := <-outCh:
			assert.True(t, got.endedByLNS, "iteration %d: a CDN is the LNS hanging up", i)
			assert.Equal(t, uint16(2), got.result, "iteration %d: the reason must already be there", i)
			assert.Equal(t, uint16(6), got.errCode, "iteration %d", i)
			assert.Equal(t, "call cleared", got.msg, "iteration %d", i)
		case <-time.After(waitFor):
			t.Fatalf("iteration %d: the session never closed", i)
		}
	}
}

// An LNS that accepts says nothing, so nothing is recorded either: a zero
// result is how the caller tells "the LNS ended this" from "it did not".
func TestCloseReasonReflectsHowTheSessionEnded(t *testing.T) {
	t.Run("a live session that the LAC then closes", func(t *testing.T) {
		tun, f := establishTunnel(t, 0)
		s := establishSession(t, tun, f)

		f.write(append(EncodeDataHeader(lacTunnelID, s.localSessionID),
			0x80, 0x21, 0x01, 0x01, 0x00, 0x04))
		proto, _, err := recvPPPParts(s)
		require.NoError(t, err)
		require.Equal(t, uint16(0x8021), proto)

		result, errCode, msg := s.CloseReason()
		assert.Zero(t, result)
		assert.Zero(t, errCode)
		assert.Empty(t, msg)

		s.Close()
		result, errCode, msg = s.CloseReason()
		assert.Zero(t, result, "the LAC hanging up is not a reason from the LNS")
		assert.Zero(t, errCode)
		assert.Empty(t, msg)
	})

	// A StopCCN kills every session in the tunnel (RFC 2661 s3.3) and carries a
	// Result Code of its own. It is a teardown of the control connection, not the
	// LNS hanging up on one subscriber, and the LAC has to be able to tell its
	// client which happened.
	t.Run("a StopCCN is a tunnel teardown, not the LNS clearing this call", func(t *testing.T) {
		tun, f := establishTunnel(t, 0)
		s := establishSession(t, tun, f)

		f.send(uint16(tun.ns.Load()), 0, BuildStopCCN(lnsTunnelID, 2, 6, "shutting down"))

		select {
		case <-s.closed:
		case <-time.After(waitFor):
			t.Fatal("a StopCCN must close the sessions it implicitly terminated")
		}
		assert.False(t, s.EndedByLNS(), "a tunnel-level teardown is not a per-call disconnect")

		result, errCode, msg := s.CloseReason()
		assert.Equal(t, uint16(2), result)
		assert.Equal(t, uint16(6), errCode)
		assert.Equal(t, "shutting down", msg)
	})
}

// A later CDN replaces an earlier one wholesale: every field of the triple is
// overwritten, including back to zero. Nothing merges the two.
func TestNoteCloseReasonOverwritesTheWholeTriple(t *testing.T) {
	s := testSession(t)

	result, errCode, msg := s.CloseReason()
	assert.Zero(t, result)
	assert.Zero(t, errCode)
	assert.Empty(t, msg)

	s.noteCloseReason(2, 6, "first")
	s.noteCloseReason(3, 0, "")
	result, errCode, msg = s.CloseReason()
	assert.Equal(t, uint16(3), result)
	assert.Zero(t, errCode, "the second CDN's zero error replaces the first's 6")
	assert.Empty(t, msg, "and its absent message replaces the first's text")
}

// The writer is recvLoop and the reader is whichever goroutine is waiting on
// AwaitAuthOutcome, so the three fields have to move as one: a reader must
// never see one CDN's result code paired with another's message. Both sides
// take closeMu, and this runs them against each other for real -- under -race
// as well, which is what would catch the mutex being dropped.
func TestCloseReasonIsNeverObservedHalfWritten(t *testing.T) {
	s := testSession(t)

	// Each triple is internally consistent, and no field value is shared
	// between them, so any mixture is detectable.
	triples := []struct {
		result  uint16
		errCode uint16
		msg     string
	}{
		{2, 6, "authorization failure"},
		{3, 11, "administrative reason"},
		{4, 2, "no resources"},
	}
	valid := func(result, errCode uint16, msg string) bool {
		if result == 0 && errCode == 0 && msg == "" {
			return true // not yet written by anyone
		}
		for _, tr := range triples {
			if tr.result == result && tr.errCode == errCode && tr.msg == msg {
				return true
			}
		}
		return false
	}

	const rounds = 2000
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, tr := range triples {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range rounds {
				s.noteCloseReason(tr.result, tr.errCode, tr.msg)
			}
		}()
	}

	readerErr := make(chan string, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		<-start
		for range rounds * len(triples) {
			result, errCode, msg := s.CloseReason()
			if !valid(result, errCode, msg) {
				select {
				case readerErr <- fmt.Sprintf("torn read: result=%d errCode=%d msg=%q", result, errCode, msg):
				default:
				}
				return
			}
		}
	}()

	close(start)
	wg.Wait()
	<-readerDone
	select {
	case msg := <-readerErr:
		t.Fatal(msg)
	default:
	}

	// And after all that, what is stored is still one whole triple.
	result, errCode, msg := s.CloseReason()
	assert.True(t, valid(result, errCode, msg),
		"the settled value must be one of the triples that was written, got %d/%d/%q", result, errCode, msg)
	assert.NotZero(t, result, "something was written")
}

// A CDN that leaves the header Session zero has to be resolved by its Assigned
// Session ID AVP -- and with more than one call on the tunnel, resolved to the
// right one.
//
// handleCDN prefers the header because RFC 2661 s3.1 makes it authoritative, and
// falls back to the AVP for peers that leave it zero. The fallback scans the
// session map comparing remote IDs, and a scan that stopped at the first entry,
// or compared the wrong field, would disconnect somebody else's subscriber. That
// is silent: the wrong call simply drops. Only a tunnel carrying at least two
// calls can tell the two behaviours apart, which is why one session is not
// enough to test this.
func TestCDNWithoutAHeaderSessionResolvesToTheRightCallAmongSeveral(t *testing.T) {
	// Four calls, and the CDN names the last. A fallback that returned whichever
	// session it reached first would be right by luck one time in four -- and Go
	// randomises map iteration, so the luck is redrawn every run. Repeating the
	// whole scenario drives the chance of a broken implementation slipping
	// through to about one in a thousand, which is the difference between a test
	// that catches this and one that reports it as a flake.
	const rounds = 5
	lnsSIDs := []uint16{0x0801, 0x0902, 0x0A03, 0x0B04}

	for round := 0; round < rounds; round++ {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			tun, f := establishTunnel(t, 0)

			sessions := make([]*Session, 0, len(lnsSIDs))
			for _, id := range lnsSIDs {
				s := establishSessionAs(t, tun, f, id)
				require.Equal(t, id, s.remoteSID())
				sessions = append(sessions, s)
			}
			require.Equal(t, len(lnsSIDs), tun.SessionCount())

			victim := sessions[len(sessions)-1]
			victimSID := lnsSIDs[len(lnsSIDs)-1]

			// Header Session deliberately 0, so only the AVP identifies the call.
			f.send(uint16(tun.ns.Load()), 0, BuildCDN(victimSID, 2, 6, "victim is done"))

			ack := f.mustNextPacket()
			require.True(t, ack.zlb, "the CDN is acknowledged, got %x", ack.raw)
			f.barrier(tun)

			select {
			case <-victim.closed:
			case <-time.After(waitFor):
				t.Fatalf("the CDN named session %#x by AVP and it is still open", victimSID)
			}

			for i, s := range sessions[:len(sessions)-1] {
				select {
				case <-s.closed:
					t.Fatalf("the CDN named %#x, but session %d (%#x) was disconnected: "+
						"the fallback resolved to the wrong call", victimSID, i, s.remoteSID())
				default:
				}
				result, _, msg := s.CloseReason()
				assert.Zerof(t, result, "session %d was not the subject of any CDN", i)
				assert.Emptyf(t, msg, "session %d was not the subject of any CDN", i)
			}

			result, errCode, msg := victim.CloseReason()
			assert.Equal(t, uint16(2), result)
			assert.Equal(t, uint16(6), errCode)
			assert.Equal(t, "victim is done", msg)
		})
	}
}
