package logs

import (
	"net"
	"net/http"
	"time"
)

type responseRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.size += n
	return n, err
}

// HTTPMiddleware returns a middleware that logs each HTTP request.
func HTTPMiddleware(logger Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}

			logger.Info("http",
				String("method", r.Method),
				String("path", r.URL.Path),
				Int("status", rec.status),
				Dur("duration", time.Since(start)),
				Int("size", rec.size),
				String("remote", host),
			)
		})
	}
}
