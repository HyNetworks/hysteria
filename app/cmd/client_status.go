package cmd

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/pppbridge"
)

// pppStatusEnv names a file where a terminal PPP failure reason is recorded.
//
// In nospawn mode hysteria runs as pppd's pty child, so the only thing netifd
// ever sees is pppd's exit code -- and a hangup looks identical whether the
// password was wrong or the network blinked. netifd would therefore restart the
// interface forever against a credential that can never work, showing a generic
// pppd error. The OpenWrt protocol handler sets this variable and reads the file
// back in its teardown, which is where it can call proto_notify_error with
// something useful and proto_block_restart to stop the loop.
const pppStatusEnv = "HYSTERIA_PPP_STATUS"

// pppStateEnv names a file describing whether this link is connected right now.
//
// The distinction from pppStatusEnv above is the whole point of having both. The
// status file answers "should netifd stop retrying this interface": one question
// with one answer, written only for the reasons that are worth acting on. This
// answers "is this particular server connected", which a Multilink bundle has one
// of per link and asks continuously.
//
// It has to come from here because nothing else can answer it. From outside, a
// client whose QUIC handshake is being refused every two seconds is exactly as
// alive as one carrying traffic, and pppd exposes nothing about the transport
// underneath it. The OpenWrt handler points this at a per-slot file and its
// status collector reads it back.
const pppStateEnv = "HYSTERIA_PPP_STATE"

// PPP status reasons. These are the strings the netifd handler matches on and
// that luci-proto-hysteria registers for display, so they are a contract.
const (
	pppStatusAuthFailed = "AUTH_FAILED"
)

// writePPPStateUp records that this link's transport reached its server and the
// server accepted a PPP session, along with the MTU that session settled on.
//
// Called when the session is established rather than when the QUIC connection
// is, because those are not the same fact: a reachable server that refuses the
// session leaves a connection up and carries nothing.
//
// The MTU is here because nospawn is exactly the case that cannot act on it:
// pppd is the parent and fixed its MRU before this process started. Publishing
// it is the only way the number reaches anything that *can* act -- the protocol
// handler, which owns pppd's command line and can rebuild the link with it. A
// zero means the server reported none and the handler should leave its
// configuration alone.
func writePPPStateUp(linkMRU int) {
	contents := "state=up\n"
	if linkMRU > 0 {
		contents += "mtu=" + strconv.Itoa(linkMRU) + "\n"
	}
	writePPPStateFile(contents)
}

// writePPPStateDown records that this link is not connected, with whatever the
// far end said about why.
//
// Unlike writePPPStatus this reports every reason, not only the permanent ones.
// A transient failure is exactly what an operator staring at one dark link in a
// bundle needs named -- "the LNS disconnected the session" and "the credential
// was refused" call for different responses, and both look like a dark link.
func writePPPStateDown(err error) {
	var b strings.Builder
	b.WriteString("state=down\n")

	reason, detail := pppFailureReason(err)
	if reason != "" {
		b.WriteString("reason=" + reason + "\n")
	}
	if detail != "" {
		b.WriteString("detail=" + detail + "\n")
	}
	writePPPStateFile(b.String())
}

// pppFailureReason maps an error onto the reason code and free text the status
// collector reports. The codes are the same contract as writePPPStatus's --
// ReasonCode.String() on one side, the strings luci-proto-hysteria registers on
// the other.
func pppFailureReason(err error) (reason, detail string) {
	if err == nil {
		return "", ""
	}
	var authErr coreErrs.AuthError
	var linkDown *pppbridge.LinkDownError
	switch {
	case errors.As(err, &authErr):
		return pppStatusAuthFailed, ""
	case errors.As(err, &linkDown):
		return linkDown.Reason.Code.String(), sanitizePPPDetail(linkDown.Reason.Message)
	default:
		// Deliberately not err.Error() as the detail. Everything reaching here is
		// local -- a dial that failed, a transport that closed -- and its text is
		// a Go error string rather than anything a subscriber can act on. The code
		// says as much as is true.
		return "LINK_DOWN", ""
	}
}

// sanitizePPPDetail makes a message from the far end safe to put in a
// key=value file.
//
// The text is chosen by the LNS and passed through verbatim by design, so it is
// the one field here an attacker upstream controls. The file is read a line at a
// time by a POSIX shell, which means a newline in this value does not corrupt
// the field -- it invents a new one, and "detail=x\nstate=up" would report a
// dead link as carrying traffic. Length is capped for the same reason /var/run
// is tmpfs.
func sanitizePPPDetail(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// writePPPStateFile replaces the state file with the given contents.
//
// Written to a temporary name in the same directory and renamed, because a
// reader arriving between the truncate and the write of a plain create sees an
// empty file and reports a working link as unknown. rename(2) has no such
// window. The shell side does the same thing for the file beside this one.
//
// Best effort throughout: a link must never fail because its status could not be
// described.
func writePPPStateFile(contents string) {
	writeFileAtomically(os.Getenv(pppStateEnv), contents)
}

// writeFileAtomically replaces path with contents, or does nothing if path is
// empty. Written to a temporary and renamed: a reader arriving between the
// truncate and the write of a plain redirect sees an empty file, and the readers
// here poll several times a minute.
func writeFileAtomically(path, contents string) {
	if path == "" {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(contents), 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
	}
}

// pppMTUEnv names a file recording the MTU a session negotiated, so that the
// next link can be built around it.
//
// nospawn is both the case that needs this and the case that can use the number
// no other way: pppd is the parent, its MRU came off a command line built before
// this process existed, and nothing here can give it another one. Writing the
// figure where the protocol handler reads it at the next bring-up is the only
// route from "the transport measured this" to "pppd is configured with it".
//
// The file records what the figure was measured against as well as the figure.
// A learned MTU is only meaningful for the configuration that produced it: an
// operator who changes ppp.mtu is asking for the measurement to be redone, and a
// stale file that silently outranked them would be worse than no file at all.
const pppMTUEnv = "HYSTERIA_PPP_MTU"

// writePPPLearnedMTU records a negotiated MTU that came out below the configured
// one. Anything else is not worth recording: equal figures teach the next link
// nothing, and a larger one cannot happen -- the configured MRU is what this
// client offered as its own ceiling, so the negotiated result is bounded by it.
func writePPPLearnedMTU(configuredMRU, negotiatedMRU int) {
	if configuredMRU <= 0 || negotiatedMRU <= 0 || negotiatedMRU >= configuredMRU {
		return
	}
	writeFileAtomically(os.Getenv(pppMTUEnv),
		"mtu="+strconv.Itoa(negotiatedMRU)+"\nfor="+strconv.Itoa(configuredMRU)+"\n")
}

// writePPPStatus records why PPP mode stopped, when the reason is one the
// protocol handler should act on. A nil error, an unset variable, or a failure
// that is worth retrying all write nothing.
func writePPPStatus(err error) {
	path := os.Getenv(pppStatusEnv)
	if path == "" || err == nil {
		return
	}
	reason := ""
	var authErr coreErrs.AuthError
	var linkDown *pppbridge.LinkDownError
	switch {
	case errors.As(err, &authErr):
		// The Hysteria2 handshake itself was refused.
		reason = pppStatusAuthFailed
	case errors.As(err, &linkDown) && linkDown.Reason.Code.Permanent():
		// The far side explained why, and retrying cannot fix it -- a refused
		// subscriber credential, or a realm that does not exist.
		reason = linkDown.Reason.Code.String()
	}
	if reason == "" {
		return
	}
	// Best effort: if this cannot be written the handler simply falls back to
	// pppd's exit code, which is the behaviour without it.
	_ = os.WriteFile(path, []byte(reason+"\n"), 0o600)
}

// pppRestartFloor is how long this process must have been alive before it is
// allowed to exit on a failure while it is pppd's pty child.
//
// Nothing between here and netifd rate-limits a redial in that mode. pppd is run
// without persist -- it has to exit so the protocol handler's teardown can read
// the status file and decide whether the failure is worth retrying at all -- so
// pppd's own holdoff never comes into play, and netifd restarts the interface as
// soon as the command returns. The redial rate is therefore exactly this
// process's exit rate. When the underlay is gone the QUIC dial fails with
// ENETUNREACH before it reaches the wire, which turns a dropped upstream into
// dozens of pppd spawns a second.
//
// A flat floor rather than backoff that grows: each restart is a fresh process,
// so growing it would mean persisting an attempt count somewhere and reasoning
// about when to clear it -- and a count left behind by an outage that has since
// ended delays the reconnect that would have worked. One attempt every five
// seconds is not a storm, and is about the rate an ordinary PPPoE redial runs at.
const pppRestartFloor = 5 * time.Second

var pppProcStart = time.Now()

// holdPPPRestart delays a failing exit until this process has been alive for
// pppRestartFloor.
//
// It keys off pppStatusEnv because that variable is set by the protocol handler
// and by nothing else, which makes it the available signal for "this process is
// pppd's pty child and its exit is a redial". A session that ran longer than the
// floor sleeps for nothing, which is every session that actually carried traffic.
//
// Sleeping holds the pty open with nothing answering on it. pppd retries LCP
// ConfReq every three seconds and gives up only after ten of them, so a pause
// this short passes unnoticed; pppd still sees the hangup when this process
// exits, exactly as it would have.
func holdPPPRestart() {
	if d := pppRestartDelay(os.Getenv(pppStatusEnv), time.Since(pppProcStart)); d > 0 {
		time.Sleep(d)
	}
}

// pppRestartDelay is the decision holdPPPRestart acts on, split out so it can be
// tested without spending the wall-clock time it describes.
func pppRestartDelay(statusPath string, alive time.Duration) time.Duration {
	if statusPath == "" {
		return 0
	}
	// Clamped at both ends. time.Since reads the monotonic clock so a negative
	// lifetime does not arise today, but the subtraction below would turn one
	// into a delay longer than the floor -- the opposite of what a floor is.
	if alive < 0 {
		alive = 0
	}
	if d := pppRestartFloor - alive; d > 0 {
		return d
	}
	return 0
}
