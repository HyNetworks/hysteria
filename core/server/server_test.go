package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMasqHandlerStripsHysteriaProtocolHeaders(t *testing.T) {
	t.Parallel()
	var received *http.Request
	var body string
	h := &h3sHandler{config: &Config{MasqHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r
		var err error
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		body = string(bodyBytes)
		w.WriteHeader(http.StatusNoContent)
	})}}
	req := httptest.NewRequest(http.MethodPost, "https://hysteria/auth", strings.NewReader("backend body"))
	req.Header.Set(protocol.RequestHeaderAuth, "real secret")
	req.Header.Set(protocol.CommonHeaderCCRX, "123456")
	req.Header.Set(protocol.CommonHeaderPadding, "random padding")
	req.Header.Set("X-Application", "preserved")
	recorder := httptest.NewRecorder()

	h.masqHandler(recorder, req)

	require.NotNil(t, received)
	assert.Empty(t, received.Header.Get(protocol.RequestHeaderAuth))
	assert.Empty(t, received.Header.Get(protocol.CommonHeaderCCRX))
	assert.Empty(t, received.Header.Get(protocol.CommonHeaderPadding))
	assert.Equal(t, "preserved", received.Header.Get("X-Application"))
	assert.Equal(t, "backend body", body)
	assert.Equal(t, "real secret", req.Header.Get(protocol.RequestHeaderAuth), "the caller's request must not be mutated")
	assert.Equal(t, http.StatusNoContent, recorder.Code)
}
