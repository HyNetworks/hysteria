package http

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/core/v2/client"
)

const (
	testCertFile = "test.crt"
	testKeyFile  = "test.key"
)

type mockHyClient struct{}

func (c *mockHyClient) TCP(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func (c *mockHyClient) UDP() (client.HyUDPConn, error) {
	return nil, errors.New("not implemented")
}

func (c *mockHyClient) PPP(dataStreams, maxFrameSize int) (*client.PPPConn, error) {
	return nil, errors.New("not implemented")
}

func (c *mockHyClient) RemoteAddr() net.Addr {
	return nil
}

func (c *mockHyClient) Close() error {
	return nil
}

func TestServer(t *testing.T) {
	// Start the server
	l, err := net.Listen("tcp", "127.0.0.1:18080")
	assert.NoError(t, err)
	defer l.Close()
	s := &Server{
		HyClient: &mockHyClient{},
	}
	go s.Serve(l)

	// Start a test HTTP & HTTPS server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("control is an illusion"))
	})
	go http.ListenAndServe("127.0.0.1:18081", nil)
	go http.ListenAndServeTLS("127.0.0.1:18082", testCertFile, testKeyFile, nil)

	// Run the Python test script
	cmd := exec.Command("python", "server_test.py")
	// Suppress HTTPS warning text from Python.
	// Extend the inherited environment (os.Environ()) rather than replacing
	// it — a non-nil cmd.Env replaces the whole environment, which would
	// strip PATH/VIRTUAL_ENV and break the uv-managed Python interpreter.
	cmd.Env = append(os.Environ(), "PYTHONWARNINGS=ignore:Unverified HTTPS request")
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err)
	assert.Equal(t, "OK", strings.TrimSpace(string(out)))
}

func TestServerBasicAuthUsesStandardBase64(t *testing.T) {
	authCalled := false
	s := &Server{
		HyClient: &mockHyClient{},
		AuthFunc: func(username, password string) bool {
			authCalled = true
			return username == string([]byte{0xff}) && password == ""
		},
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(time.Second))
	go s.dispatch(serverConn)

	// "/zo=" is standard Base64 for []byte{0xff, ':'}. It is valid Basic Auth,
	// but it is not valid URL-safe Base64.
	_, err := clientConn.Write([]byte("CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nProxy-Authorization: Basic /zo=\r\n\r\n"))
	assert.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.True(t, authCalled)
	assert.NotEqual(t, http.StatusProxyAuthRequired, resp.StatusCode)
}
