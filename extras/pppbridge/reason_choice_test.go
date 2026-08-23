package pppbridge

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Both ends can have an opinion about why a session ended, and they see
// different things. The server knows what an LNS said; the client is the only
// side that can tell its full-size frames stopped arriving. chooseReason is
// where that is settled.
func TestChooseReason(t *testing.T) {
	narrowed := SessionReason{Code: ReasonPathNarrowed}
	linkDown := SessionReason{Code: ReasonLinkDown}
	serverEnded := SessionReason{Code: ReasonLinkDown, Message: "server-side PPP session ended"}
	authFailed := SessionReason{Code: ReasonAuthFailed, Result: 2, Error: 6, Message: "bad password"}
	lnsGone := SessionReason{Code: ReasonLNSDisconnected, Message: "session cleared by operator"}

	tests := []struct {
		name   string
		local  SessionReason
		remote *SessionReason
		want   SessionReason
		why    string
	}{
		{
			name: "no reason arrived", local: narrowed, remote: nil, want: narrowed,
			why: "a silent control stream leaves what this side worked out",
		},
		{
			name: "the server explains a generic link down", local: linkDown, remote: &lnsGone,
			want: lnsGone,
			why:  "anything specific beats the default",
		},
		{
			name:  "a vague server reason must not erase a local diagnosis",
			local: narrowed, remote: &serverEnded, want: narrowed,
			why: "only this side can see that the path stopped carrying full-size frames, " +
				"and PATH_NARROWED is what tells the caller to rebuild smaller",
		},
		{
			name:  "a permanent verdict wins even over a local diagnosis",
			local: narrowed, remote: &authFailed, want: authFailed,
			why: "a refused credential is the one answer that changes what happens next, " +
				"and only the server can know it",
		},
		{
			name:  "a non-permanent server reason does not displace a local one",
			local: narrowed, remote: &lnsGone, want: narrowed,
			why: "both are worth retrying, so the more specific one is kept",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, chooseReason(tt.local, tt.remote), tt.why)
		})
	}
}

// The rule has to hold for every permanent code, not just the one above: those
// are exactly the codes that stop a client retrying, so they must always reach
// it.
func TestChooseReasonNeverDropsAPermanentVerdict(t *testing.T) {
	for _, code := range []ReasonCode{
		ReasonUnknown, ReasonLinkDown, ReasonAuthFailed, ReasonNoRoute,
		ReasonNoLNS, ReasonLNSUnreachable, ReasonLNSDisconnected, ReasonPathNarrowed,
	} {
		if !code.Permanent() {
			continue
		}
		remote := SessionReason{Code: code}
		for _, local := range []SessionReason{
			{Code: ReasonLinkDown},
			{Code: ReasonPathNarrowed},
		} {
			assert.Equal(t, remote, chooseReason(local, &remote),
				"%s must survive a local %s", code, local.Code)
		}
	}
}
