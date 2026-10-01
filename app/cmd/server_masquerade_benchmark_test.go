package cmd

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type discardBenchmarkResponseWriter struct {
	header http.Header
	status int
}

func (w *discardBenchmarkResponseWriter) Header() http.Header {
	return w.header
}

func (w *discardBenchmarkResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *discardBenchmarkResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(body), nil
}

func BenchmarkMasqueradeProxy(b *testing.B) {
	payload := make([]byte, 4*1024)
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	})
	socketPath, _ := startUnixHTTPServer(b, upstreamHandler)
	tcpServer := httptest.NewServer(upstreamHandler)
	b.Cleanup(tcpServer.Close)

	for _, test := range []struct {
		name   string
		target string
	}{
		{name: "unix", target: socketPath},
		{name: "tcp", target: tcpServer.URL},
	} {
		b.Run(test.name, func(b *testing.B) {
			handler, err := newMasqueradeProxyHandler(serverConfigMasqueradeProxy{URL: test.target})
			if err != nil {
				b.Fatal(err)
			}
			if closer, ok := handler.(interface{ CloseIdleConnections() }); ok {
				b.Cleanup(closer.CloseIdleConnections)
			}

			var failures atomic.Int64
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					request := httptest.NewRequest(http.MethodGet, "https://front.example/resource", nil)
					response := &discardBenchmarkResponseWriter{header: make(http.Header)}
					handler.ServeHTTP(response, request)
					if response.status != http.StatusOK {
						failures.Add(1)
					}
				}
			})
			b.StopTimer()
			if count := failures.Load(); count != 0 {
				b.Fatalf("%d proxy requests failed", count)
			}
		})
	}
}
