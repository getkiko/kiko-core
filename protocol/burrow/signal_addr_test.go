package burrow

import "testing"

// buildSignalAddr must turn signal_path into the path prefix of SignalAddr,
// and a path in server wins.
func TestBuildSignalAddr(t *testing.T) {
	cases := []struct {
		name       string
		server     string
		port       uint16
		signalPath string
		want       string
	}{
		{
			name: "bare host:port without path", server: "1.2.3.4", port: 9960,
			want: "1.2.3.4:9960",
		},
		{
			name: "bare host:port with prefix", server: "1.2.3.4", port: 9960, signalPath: "/abc",
			want: "ws://1.2.3.4:9960/abc",
		},
		{
			name: "prefix without leading slash", server: "1.2.3.4", port: 9960, signalPath: "abc",
			want: "ws://1.2.3.4:9960/abc",
		},
		{
			name: "prefix with trailing slash", server: "1.2.3.4", port: 9960, signalPath: "/abc/",
			want: "ws://1.2.3.4:9960/abc",
		},
		{
			name: "URL gets port and prefix", server: "ws://example.com", port: 9960, signalPath: "/abc",
			want: "ws://example.com:9960/abc",
		},
		{
			name: "wss keeps scheme", server: "wss://example.com:8443", port: 0, signalPath: "/a/b",
			want: "wss://example.com:8443/a/b",
		},
		{
			name: "path in server wins", server: "ws://example.com:9960/xyz", port: 0, signalPath: "/abc",
			want: "ws://example.com:9960/xyz",
		},
		{
			name: "server without path or signal_path", server: "ws://example.com:9960", port: 0,
			want: "ws://example.com:9960",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildSignalAddr(tc.server, tc.port, tc.signalPath); got != tc.want {
				t.Errorf("buildSignalAddr(%q,%d,%q) = %q, expected %q",
					tc.server, tc.port, tc.signalPath, got, tc.want)
			}
		})
	}
}
