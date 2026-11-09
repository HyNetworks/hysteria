package outbounds

import (
	"net"
	"testing"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/outbounds/acl"

	"github.com/stretchr/testify/assert"
)

func TestACLEngine(t *testing.T) {
	ob1, ob2, ob3 := &mockPluggableOutbound{}, &mockPluggableOutbound{}, &mockPluggableOutbound{}
	obs := []OutboundEntry{
		{"ob1", ob1},
		{"ob2", ob2},
		{"ob3", ob3},
		{"direct", ob2},
	}
	rules, err := acl.TranslateText(`
ob2(google.com,tcp)
ob3(youtube.com,udp)
ob1 (1.1.1.1/24,*,8.8.8.8)
Direct(cia.gov)
reJect(nsa.gov)
`, "")
	assert.NoError(t, err)
	engine, err := NewACLEngine(rules, obs, nil)
	assert.NoError(t, err)

	// No match, default, should be the first (ob1)
	ob1.EXPECT().TCP(&AddrEx{Host: "example.com"}).Return(nil, nil).Once()
	conn, err := engine.TCP(&AddrEx{Host: "example.com"})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// Match ob2
	ob2.EXPECT().TCP(&AddrEx{Host: "google.com"}).Return(nil, nil).Once()
	conn, err = engine.TCP(&AddrEx{Host: "google.com"})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// Match ob3
	ob3.EXPECT().UDP(&AddrEx{Host: "youtube.com"}).Return(nil, nil).Once()
	udpConn, err := engine.UDP(&AddrEx{Host: "youtube.com"})
	assert.NoError(t, err)
	assert.Nil(t, udpConn)

	// Match ob1 hijack IP
	ob1.EXPECT().TCP(&AddrEx{Host: "8.8.8.8", ResolveInfo: &ResolveInfo{IPv4: net.ParseIP("8.8.8.8").To4()}}).Return(nil, nil).Once()
	conn, err = engine.TCP(&AddrEx{ResolveInfo: &ResolveInfo{IPv4: net.ParseIP("1.1.1.22")}})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// direct should be ob2 as we override it
	ob2.EXPECT().TCP(&AddrEx{Host: "cia.gov"}).Return(nil, nil).Once()
	conn, err = engine.TCP(&AddrEx{Host: "cia.gov"})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// reject
	conn, err = engine.TCP(&AddrEx{Host: "nsa.gov"})
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestACLEngineAuthRouting(t *testing.T) {
	alice, others := &mockPluggableOutbound{}, &mockPluggableOutbound{}
	obs := []OutboundEntry{
		{"others", others},
		{"alice_exit", alice},
	}
	rules, err := acl.TranslateText("reject(blocked.example)", "rules[1]")
	assert.NoError(t, err)
	rules = append([]acl.Rule{
		{Outbound: "alice_exit", Match: `auth.id == "alice"`, Source: "rules[0]"},
	}, rules...)
	engine, err := NewACLEngine(rules, obs, nil)
	assert.NoError(t, err)

	aliceInfo := &server.RequestInfo{AuthID: "alice", ClientAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}}
	bobInfo := &server.RequestInfo{AuthID: "bob", ClientAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1}}

	// Same destination, different auth IDs
	alice.EXPECT().TCP(&AddrEx{Host: "example.com", Port: 443, Info: aliceInfo}).Return(nil, nil).Once()
	_, err = engine.TCP(&AddrEx{Host: "example.com", Port: 443, Info: aliceInfo})
	assert.NoError(t, err)

	others.EXPECT().TCP(&AddrEx{Host: "example.com", Port: 443, Info: bobInfo}).Return(nil, nil).Once()
	_, err = engine.TCP(&AddrEx{Host: "example.com", Port: 443, Info: bobInfo})
	assert.NoError(t, err)

	alice.EXPECT().UDP(&AddrEx{Host: "example.com", Port: 443, Info: aliceInfo}).Return(nil, nil).Once()
	_, err = engine.UDP(&AddrEx{Host: "example.com", Port: 443, Info: aliceInfo})
	assert.NoError(t, err)

	alice.EXPECT().CheckUDP(&AddrEx{Host: "example.com", Port: 53, Info: aliceInfo}).Return(nil).Once()
	assert.NoError(t, engine.CheckUDP(&AddrEx{Host: "example.com", Port: 53, Info: aliceInfo}))

	// Legacy rule after the auth rule still applies to others
	_, err = engine.TCP(&AddrEx{Host: "blocked.example", Port: 443, Info: bobInfo})
	assert.Error(t, err)

	// No Info (e.g. a pipeline used without the adapter): auth.id is empty
	others.EXPECT().TCP(&AddrEx{Host: "example.com", Port: 443}).Return(nil, nil).Once()
	_, err = engine.TCP(&AddrEx{Host: "example.com", Port: 443})
	assert.NoError(t, err)
}
