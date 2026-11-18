//go:build go1.26

package h2

import (
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestServeForH2Spec serves Serve on a TLS listener for the h2spec conformance
// tool (https://github.com/summerwind/h2spec). It is skipped unless
// H2SPEC_PORT is set:
//
//	H2SPEC_PORT=18443 go test -run TestServeForH2Spec ./common/mitm/h2/ &
//	h2spec -h 127.0.0.1 -p 18443 -t -k --strict
func TestServeForH2Spec(t *testing.T) {
	port := os.Getenv("H2SPEC_PORT")
	if port == "" {
		t.Skip("H2SPEC_PORT not set")
	}
	_, e := httpProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "ok")
	}), func(o *Options) { o.ServerName = "127.0.0.1" })
	// Forward the fixed port to the proxy listener.
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", e.addr)
			if err != nil {
				c.Close()
				continue
			}
			go func() { io.Copy(up, c); up.Close() }()
			go func() { io.Copy(c, up); c.Close() }()
		}
	}()
	secs, _ := strconv.Atoi(os.Getenv("H2SPEC_SECONDS"))
	if secs == 0 {
		secs = 300
	}
	time.Sleep(time.Duration(secs) * time.Second)
}
