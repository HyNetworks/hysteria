package pppbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/ppp"
	"go.uber.org/zap"
)

// DialFn is called by the Bridge to establish a PPP session.
// It returns the control stream, data I/O, a close function, and an error.
// Return permanentDialError to stop retry attempts.
type DialFn func() (control io.ReadWriteCloser, data ppp.PPPDataIO, closeFn func(), err error)

// permanentDialError wraps errors that should not be retried.
type permanentDialError struct{ err error }

func (e permanentDialError) Error() string { return e.err.Error() }
func (e permanentDialError) Unwrap() error { return e.err }

// errLinkDown reports that the Hysteria2 connection carrying the PPP session was
// lost. LinkDownError carries it along with whatever the server said about why.
var errLinkDown = errors.New("ppp: hysteria2 link lost")

// LinkDownError is what Run returns when an established link goes away. Reason is
// the server's explanation if one arrived, so a caller can tell a refused
// credential from a flapping uplink instead of guessing.
type LinkDownError struct {
	Reason SessionReason
}

func (e *LinkDownError) Error() string {
	if e.Reason.Message != "" {
		return fmt.Sprintf("%s: %s (%s)", errLinkDown, e.Reason.Code, e.Reason.Message)
	}
	return fmt.Sprintf("%s: %s", errLinkDown, e.Reason.Code)
}

func (e *LinkDownError) Unwrap() error { return errLinkDown }

// Bridge connects a pppd to a Hysteria2 PPP session.
//
// Every PPP frame travels the same way, through PPPDataIO: LCP, authentication
// and user data alike. ppp.dataStreams picks which transport that is -- 0 uses
// QUIC datagrams, giving PPP the unreliable link it was designed for, and N > 0
// uses N reliable QUIC streams for paths where datagrams are unusable. Nothing
// here inspects a frame to make that choice, so the transport does no PPP
// protocol parsing at all.
//
// The frame pumping itself lives in relay, shared with the server side: the
// client's endpoint is its pppd, the server's is either its own pppd or an L2TP
// session to an LNS. Only the endpoint differs.
//
// The Hysteria2 connection is the link. It comes up once, carries one PPP
// session, and when it goes it takes the session with it -- Run returns and the
// caller rebuilds both. There is deliberately no attempt to re-dial underneath a
// live pppd: the server releases the address and kills its pppd the moment the
// connection drops, so a client holding its old PPP state would be using an
// address that has already been reassigned.
//
// PPP events do not reach the link. A Terminate-Request or a renegotiation is
// just another frame; only pppd exiting ends things, and then there is nothing
// left to carry.
//
// When NoSpawn is set no child is spawned; the bridge uses its own stdin/stdout,
// so an external pppd can own the process -- pppd's pty option, as netifd
// protocol handlers use.
type Bridge struct {
	PPPDPath string
	PPPDArgs []string
	Sudo     bool
	NoSpawn  bool
	Logger   *zap.Logger

	// PPPDArgsFn supplies the child's arguments once the PPP session exists, in
	// place of PPPDArgs, so they can carry the MTU the two ends negotiated rather
	// than the one this process guessed before it had anything to measure.
	//
	// Setting it also reverses the order of the two things Run starts: the
	// session is established before the child. That is the entire reason it
	// exists -- pppd reads mtu and mru once, off its command line, and there is
	// no way to tell it a different number afterwards. A negotiated MTU that
	// arrives after pppd has started is a number that can only be logged, which
	// is what this used to do.
	//
	// Spawn mode only. In NoSpawn pppd is the parent and fixed its MRU before
	// this process existed, so there are no arguments to supply and the ordering
	// stays as it was.
	PPPDArgsFn func() []string

	// ProbeInterval, ProbeGrace and ProbeFailures override the MTU probe timings.
	// Zero selects the package defaults; tests set them small so the teardown
	// decision can be exercised without a minute of wall clock.
	ProbeInterval time.Duration
	ProbeGrace    time.Duration
	ProbeFailures int

	// MTUFixed says this process did not choose the PPP MTU, so tearing the
	// session down cannot lead to a smaller one. app/internal/ppp sets it from
	// NoSpawn, which is where pppd is the parent and was configured before this
	// process existed.
	//
	// Deliberately not derived from NoSpawn. That field answers a mechanical
	// question, whether to bridge stdio instead of forking, and the test harness
	// sets it for that reason alone while still wanting the teardown behaviour.
	// Conflating the two would have made every probe test silently exercise the
	// wrong branch.
	MTUFixed bool

	// ReadReason makes Run listen on the control stream for the server's
	// explanation of why the session ended. Only the client does this: the server
	// writes reasons rather than reading them, and a server-side Bridge left
	// reading would be waiting on a message that never comes.
	ReadReason bool

	// In and Out replace stdin and stdout in NoSpawn mode. Leaving them nil
	// selects os.Stdin and os.Stdout, which is what the pppd pty case wants;
	// tests set them to a pair of pipes to drive the bridge without a real pppd.
	In  io.ReadCloser
	Out io.WriteCloser

	// Counters, when set, accumulate the PPP traffic this bridge carries, so a
	// caller outside the package can publish what one link of a bundle is doing.
	//
	// Supplied by the caller rather than owned here, because the reader outlives
	// the bridge: in spawn mode Run is called again after every link failure, and
	// a counter that restarted with each rebuild would report a link that had
	// just reconnected as having carried nothing. Leaving it nil costs nothing --
	// the relay allocates a throwaway and the pumps stay branch-free.
	Counters *Counters

	// oversizeDropped counts frames refused by the transport for being too large.
	// A non-zero value means the negotiated PPP MTU exceeds what the path carries,
	// which is otherwise invisible.
	oversizeDropped atomic.Uint64
}

// OversizeDropped returns the number of frames dropped for exceeding the
// transport's per-frame limit.
func (b *Bridge) OversizeDropped() uint64 { return b.oversizeDropped.Load() }

// childCommand returns the program and arguments to run for the PPP daemon.
//
// Separated from startChild so it can be checked without spawning anything: the
// Sudo path in particular is untestable in place, because exercising it would
// mean really invoking sudo, which either is not installed or stops to ask for a
// password. Getting the order wrong would run pppd's first argument as the
// program.
func (b *Bridge) childCommand() (name string, args []string) {
	name, args = b.PPPDPath, b.PPPDArgs
	if b.PPPDArgsFn != nil {
		args = b.PPPDArgsFn()
	}
	if b.Sudo {
		// sudo takes the real program as its first argument.
		args = append([]string{name}, args...)
		name = "sudo"
	}
	return name, args
}

func (b *Bridge) startChild(ctx context.Context) (
	reader io.Reader, writer io.WriteCloser, cleanup func(), waitFn func() error, err error,
) {
	if b.NoSpawn {
		in, out := b.In, b.Out
		if in == nil {
			in = os.Stdin
		}
		if out == nil {
			out = os.Stdout
		}
		b.Logger.Info("PPP bridge using stdio, no child spawned", zap.String("io", "stdio"))
		return in, out, func() { _ = in.Close() }, func() error { return nil }, nil
	}
	name, args := b.childCommand()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = os.Stderr

	reader, writer, cleanup, err = b.startProcess(cmd)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to start process: %w", err)
	}
	b.Logger.Info("PPP bridge child started",
		zap.Int("pid", cmd.Process.Pid), zap.String("io", bridgeIOMode))

	waitFn = func() error {
		waitErr := cmd.Wait()
		b.Logger.Debug("PPP bridge child exited", zap.Error(waitErr))
		return waitErr
	}
	return reader, writer, cleanup, waitFn, err
}

// Run starts a child process and bridges it to a PPP session obtained via dialFn.
// The caller decides whether to restart (e.g. client Serve loop).
func (b *Bridge) Run(ctx context.Context, dialFn DialFn) (runErr error) {
	// Which of the two comes up first. With PPPDArgsFn the child's arguments are
	// a function of the session, so the session has to exist to build them.
	// Without it the child goes first, which is worth keeping where it is
	// possible: a frame from pppd is the cheapest proof that there is anything
	// worth dialling for, and in NoSpawn it is the only proof available.
	dialFirst := b.PPPDArgsFn != nil && !b.NoSpawn

	var (
		control io.ReadWriteCloser
		data    ppp.PPPDataIO
		closeFn func()
	)

	if dialFirst {
		// Retrying is fine here for the same reason it is fine below: nothing has
		// been forwarded yet, so the link is not up and there is no state to be
		// inconsistent about. Less is at stake than below, in fact -- no child is
		// running to be kept waiting.
		var err error
		control, data, closeFn, err = b.dialWithRetry(ctx, dialFn)
		if err != nil {
			return err
		}
		defer closeFn()
	}

	childReader, childWriter, cleanup, waitFn, err := b.startChild(ctx)
	if err != nil {
		return err
	}

	ep := newHDLCEndpoint(childReader, childWriter)

	defer func() {
		cleanup() // close pty/pipe -> child gets SIGHUP/EOF
		if waitErr := waitFn(); runErr == nil {
			runErr = waitErr
		}
	}()

	// The first frame pppd emits brings the link up. Which frame it is does not
	// matter: pppd opens with an LCP Configure-Request and retransmits on its own
	// Restart timer if this one is lost.
	type firstFrame struct {
		frame []byte
		err   error
	}
	firstCh := make(chan firstFrame, 1)
	go func() {
		f, err := ep.RecvPPP()
		firstCh <- firstFrame{f, err}
	}()

	var first firstFrame
	select {
	case first = <-firstCh:
		if first.err != nil {
			return nil // child went away before saying anything
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	if !dialFirst {
		// Retrying here is fine: the link is not up yet, so there is no state to be
		// inconsistent about. It is only after it comes up that a drop must mean the
		// link is down.
		var err error
		control, data, closeFn, err = b.dialWithRetry(ctx, dialFn)
		if err != nil {
			return err
		}
		defer closeFn()
	}

	if err := data.SendData(first.frame); err != nil {
		b.Logger.Warn("initial frame could not be sent", zap.Error(err))
	} else if b.Counters != nil {
		// Counted here rather than by the relay, which does not exist yet.
		//
		// This frame is the one that decided the link was worth dialling for, and
		// it goes onto the transport exactly like every frame after it. Leaving it
		// out would put TxFrames one below the number of frames the link actually
		// carried -- every session, for the life of the session -- which is a small
		// error in the bytes and a wrong answer in the frame count.
		b.Counters.addTx(len(first.frame))
	}

	// The server writes a reason on the control stream as the session ends.
	// Nothing else uses that stream after the handshake.
	//
	// A nil answer means the stream ended without one, which is the common case
	// when the transport itself dropped -- both directions die together, so there
	// is no reason to wait for. Reporting that promptly rather than sitting out
	// the timeout is what keeps a plain link loss from costing a second before
	// pppd is torn down.
	reasonCh := make(chan *SessionReason, 1)
	if b.ReadReason {
		go func() {
			r, err := ReadSessionReason(control)
			if err != nil {
				reasonCh <- nil
				return
			}
			reasonCh <- &r
		}()
	}

	r := newRelay(data, ep, b.Logger, &b.oversizeDropped)
	r.ProbeInterval, r.ProbeGrace, r.ProbeFailures = b.ProbeInterval, b.ProbeGrace, b.ProbeFailures
	r.MTUFixed = b.MTUFixed
	if b.Counters != nil {
		r.counters = b.Counters
	}

	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()
	relayErr := r.run(relayCtx)

	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	// Which side failed decides the answer. If pppd went away there is nothing to
	// carry and no link problem to report -- the deferred waitFn surfaces its exit
	// status. Only a transport failure is a link that went down.
	var re *relayError
	if errors.As(relayErr, &re) && re.fromEndpoint {
		b.Logger.Debug("PPP child ended the session", zap.Error(relayErr))
		return nil
	}

	// Give the reason a moment to arrive: the server writes it as it tears down,
	// so it is usually already in flight by the time the relay noticed.
	//
	// Only a bridge that is listening waits. A server-side one is not -- it writes
	// reasons rather than reading them -- and waiting on a channel nothing will
	// ever send to would put a second between every session ending and its IP
	// being released.
	reason := SessionReason{Code: ReasonLinkDown}
	if errors.Is(relayErr, errPathNarrowed) {
		reason.Code = ReasonPathNarrowed
	}
	if b.ReadReason {
		select {
		case r := <-reasonCh:
			reason = chooseReason(reason, r)
		case <-time.After(time.Second):
		}
	}
	b.Logger.Warn("PPP link down",
		zap.String("reason", reason.Code.String()),
		zap.Bool("permanent", reason.Code.Permanent()),
		zap.Uint16("lnsResult", reason.Result),
		zap.Uint16("lnsError", reason.Error),
		zap.String("message", reason.Message))
	return &LinkDownError{Reason: reason}
}

// chooseReason settles which explanation the caller is given when both ends have
// one. remote is nil when the control stream ended without a reason.
//
// A cause diagnosed here is not replaced by a vaguer one from the far end:
// PATH_NARROWED is something only this side can see -- the server's session
// simply ended, so that is all it can say -- and losing it would cost the caller
// the one code that means "rebuild at a smaller size" rather than "retry".
//
// A permanent verdict still wins. It is the only answer that changes what the
// caller does next, and the server is the only side that can know it.
func chooseReason(local SessionReason, remote *SessionReason) SessionReason {
	if remote == nil {
		return local
	}
	if local.Code == ReasonLinkDown || remote.Code.Permanent() {
		return *remote
	}
	return local
}

// dialWithRetry brings the link up, backing off on transient failures. The child
// is not watched here: its only reader has already taken the first frame, so a
// death during the dial surfaces immediately afterwards when the relay's endpoint
// pump fails.
func (b *Bridge) dialWithRetry(
	ctx context.Context, dialFn DialFn,
) (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
	backoff := 1 * time.Second
	for {
		control, data, closeFn, err := dialFn()
		if err == nil {
			return control, data, closeFn, nil
		}
		if isPermanentDialError(err) {
			return nil, nil, nil, err
		}
		b.Logger.Warn("PPP dial failed, retrying",
			zap.Error(err), zap.Duration("backoff", backoff))
		select {
		case <-time.After(backoff):
			backoff = min(backoff*2, 30*time.Second)
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		}
	}
}

func isPermanentDialError(err error) bool {
	var pe permanentDialError
	if errors.As(err, &pe) {
		return true
	}
	// Bad credentials will not become good by waiting. Retrying an auth failure
	// hides the cause behind a restart loop, so let it out to the caller, which
	// can report it and stop.
	var ae coreErrs.AuthError
	if errors.As(err, &ae) {
		return true
	}
	var ce coreErrs.ClosedError
	return errors.As(err, &ce)
}
