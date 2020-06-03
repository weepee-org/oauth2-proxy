package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

// Server represents an HTTP server
type Server struct {
	Handler http.Handler
	Opts    *options.Options
	stop    chan struct{} // channel for waiting shutdown
}

// ListenAndServe will serve traffic on HTTP or HTTPS depending on TLS options
func (s *Server) ListenAndServe() {
	if s.Opts.TLSKeyFile != "" || s.Opts.TLSCertFile != "" {
		s.ServeHTTPS()
	} else {
		s.ServeHTTP()
	}
}

// Used with gcpHealthcheck()
const userAgentHeader = "User-Agent"
const googleHealthCheckUserAgent = "GoogleHC/1.0"
const rootPath = "/"

// gcpHealthcheck handles healthcheck queries from GCP.
func gcpHealthcheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for liveness and readiness:  used for Google App Engine
		if r.URL.EscapedPath() == "/liveness_check" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}
		if r.URL.EscapedPath() == "/readiness_check" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}

		// Check for GKE ingress healthcheck:  The ingress requires the root
		// path of the target to return a 200 (OK) to indicate the service's good health. This can be quite a challenging demand
		// depending on the application's path structure. This middleware filters out the requests from the health check by
		//
		// 1. checking that the request path is indeed the root path
		// 2. ensuring that the User-Agent is "GoogleHC/1.0", the health checker
		// 3. ensuring the request method is "GET"
		if r.URL.Path == rootPath &&
			r.Header.Get(userAgentHeader) == googleHealthCheckUserAgent &&
			r.Method == http.MethodGet {

			w.WriteHeader(http.StatusOK)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// ServeHTTP constructs a net.Listener and starts handling HTTP requests
func (s *Server) ServeHTTP() {
	HTTPAddress := s.Opts.HTTPAddress
	var scheme string

	i := strings.Index(HTTPAddress, "://")
	if i > -1 {
		scheme = HTTPAddress[0:i]
	}

	var networkType string
	switch scheme {
	case "", "http":
		networkType = "tcp"
	default:
		networkType = scheme
	}

	slice := strings.SplitN(HTTPAddress, "//", 2)
	listenAddr := slice[len(slice)-1]

	listener, err := net.Listen(networkType, listenAddr)
	if err != nil {
		logger.Fatalf("FATAL: listen (%s, %s) failed - %s", networkType, listenAddr, err)
	}
	logger.Printf("HTTP: listening on %s", listenAddr)
	s.serve(listener)
	logger.Printf("HTTP: closing %s", listener.Addr())
}

// ServeHTTPS constructs a net.Listener and starts handling HTTPS requests
func (s *Server) ServeHTTPS() {
	addr := s.Opts.HTTPSAddress
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(s.Opts.TLSCertFile, s.Opts.TLSKeyFile)
	if err != nil {
		logger.Fatalf("FATAL: loading tls config (%s, %s) failed - %s", s.Opts.TLSCertFile, s.Opts.TLSKeyFile, err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatalf("FATAL: listen (%s) failed - %s", addr, err)
	}
	logger.Printf("HTTPS: listening on %s", ln.Addr())

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
	s.serve(tlsListener)
	logger.Printf("HTTPS: closing %s", tlsListener.Addr())
}

func (s *Server) serve(listener net.Listener) {
	srv := &http.Server{Handler: s.Handler}

	// See https://golang.org/pkg/net/http/#Server.Shutdown
	idleConnsClosed := make(chan struct{})
	go func() {
		<-s.stop // wait notification for stopping server

		// We received an interrupt signal, shut down.
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	err := srv.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Printf("ERROR: http.Serve() - %s", err)
	}
	<-idleConnsClosed
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

func redirectToHTTPS(opts *options.Options, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto := r.Header.Get("X-Forwarded-Proto")
		if opts.ForceHTTPS && (r.TLS == nil || (proto != "" && strings.ToLower(proto) != "https")) {
			target := "https://" + r.Host + r.URL.Path
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
		}

		h.ServeHTTP(w, r)
	})
}
