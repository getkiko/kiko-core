package mitm

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/authority"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type testCA struct {
	certificatePath string
	keyPath         string
	certificatePEM  []byte
}

func writeTestCA(t testing.TB) testCA {
	t.Helper()
	certificatePEM, keyPEM, err := authority.Generate("Kiko Test CA", 24*time.Hour)
	require.NoError(t, err)
	directory := t.TempDir()
	ca := testCA{
		certificatePath: filepath.Join(directory, "ca.pem"),
		keyPath:         filepath.Join(directory, "ca.key"),
		certificatePEM:  certificatePEM,
	}
	require.NoError(t, os.WriteFile(ca.certificatePath, certificatePEM, 0o600))
	require.NoError(t, os.WriteFile(ca.keyPath, keyPEM, 0o600))
	return ca
}

func fileOptions(ca testCA, enabled bool, include []string, exclude []string) *option.MITMOptions {
	return &option.MITMOptions{
		Enabled: enabled,
		Certificate: &option.MITMCertificateOptions{
			Source:          C.MITMCertificateSourceFile,
			CertificatePath: ca.certificatePath,
			KeyPath:         ca.keyPath,
		},
		Hostnames: &option.MITMHostnamesOptions{Include: include, Exclude: exclude},
	}
}

func newTestEngine(t testing.TB, ctx context.Context, options *option.MITMOptions) *Engine {
	t.Helper()
	engine, err := NewEngine(ctx, log.NewNOPFactory().NewLogger("mitm"), options)
	require.NoError(t, err)
	t.Cleanup(func() { engine.Close() })
	return engine
}

type handlerOutbound struct {
	adapter.Outbound
}

func (h *handlerOutbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
}

func tlsMetadata(serverName string, destination string) *adapter.InboundContext {
	return &adapter.InboundContext{
		Network:     N.NetworkTCP,
		Protocol:    C.ProtocolTLS,
		Domain:      serverName,
		Destination: M.ParseSocksaddr(destination),
	}
}

func TestDecideOrder(t *testing.T) {
	ca := writeTestCA(t)
	include := []string{"*.example.com", "1.2.3.4"}
	exclude := []string{"skip.example.com"}
	testCases := []struct {
		name     string
		options  *option.MITMOptions
		metadata func() *adapter.InboundContext
		status   adapter.MITMStatus
		reason   string
	}{
		{"absent", nil, func() *adapter.InboundContext { return tlsMetadata("a.example.com", "10.0.0.1:443") }, adapter.MITMStatusNone, ""},
		{"disabled", fileOptions(ca, false, include, exclude), func() *adapter.InboundContext { return tlsMetadata("a.example.com", "10.0.0.1:443") }, adapter.MITMStatusNone, ""},
		{"include", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext { return tlsMetadata("a.example.com", "10.0.0.1:443") }, adapter.MITMStatusPending, ""},
		{"not included", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext { return tlsMetadata("example.org", "10.0.0.1:443") }, adapter.MITMStatusNone, ""},
		{"other port", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext { return tlsMetadata("a.example.com", "10.0.0.1:8443") }, adapter.MITMStatusNone, ""},
		{"not tls", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext {
			metadata := tlsMetadata("a.example.com", "10.0.0.1:443")
			metadata.Protocol = C.ProtocolHTTP
			return metadata
		}, adapter.MITMStatusNone, ""},
		{"no sni", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext { return tlsMetadata("", "10.0.0.1:443") }, adapter.MITMStatusNone, ""},
		{"ip include without sni", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext { return tlsMetadata("", "1.2.3.4:443") }, adapter.MITMStatusPending, ""},
		{"ip include via resolved address", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext {
			metadata := tlsMetadata("", "host.test:443")
			metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("1.2.3.4")}
			return metadata
		}, adapter.MITMStatusPending, ""},
		{"exclude wins", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext { return tlsMetadata("skip.example.com", "10.0.0.1:443") }, adapter.MITMStatusNone, ""},
		{"skip override", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext {
			metadata := tlsMetadata("a.example.com", "10.0.0.1:443")
			metadata.MITMOverride = C.MITMOverrideSkip
			return metadata
		}, adapter.MITMStatusNone, ""},
		{"force override", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext {
			metadata := tlsMetadata("skip.example.com", "10.0.0.1:443")
			metadata.MITMOverride = C.MITMOverrideForce
			return metadata
		}, adapter.MITMStatusPending, ""},
		{"force override without sni", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext {
			metadata := tlsMetadata("", "1.2.3.4:443")
			metadata.MITMOverride = C.MITMOverrideForce
			return metadata
		}, adapter.MITMStatusNone, ""},
		{"force override disabled", fileOptions(ca, false, include, exclude), func() *adapter.InboundContext {
			metadata := tlsMetadata("a.example.com", "10.0.0.1:443")
			metadata.MITMOverride = C.MITMOverrideForce
			return metadata
		}, adapter.MITMStatusNone, ""},
		{"force override not tls", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext {
			metadata := tlsMetadata("a.example.com", "10.0.0.1:443")
			metadata.Protocol = ""
			metadata.MITMOverride = C.MITMOverrideForce
			return metadata
		}, adapter.MITMStatusNone, ""},
		{"authority pending", &option.MITMOptions{
			Enabled:   true,
			Hostnames: &option.MITMHostnamesOptions{Include: include},
		}, func() *adapter.InboundContext { return tlsMetadata("a.example.com", "10.0.0.1:443") }, adapter.MITMStatusSkipped, ReasonAuthorityPending},
		{"authority pending miss", &option.MITMOptions{
			Enabled:   true,
			Hostnames: &option.MITMHostnamesOptions{Include: include},
		}, func() *adapter.InboundContext { return tlsMetadata("example.org", "10.0.0.1:443") }, adapter.MITMStatusNone, ""},
		{"connection handler outbound", fileOptions(ca, true, include, exclude), func() *adapter.InboundContext {
			metadata := tlsMetadata("a.example.com", "10.0.0.1:443")
			metadata.OutboundChain = []adapter.Outbound{&handlerOutbound{}}
			return metadata
		}, adapter.MITMStatusNone, ""},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			engine := newTestEngine(t, context.Background(), testCase.options)
			state := engine.Decide(testCase.metadata())
			if testCase.status == adapter.MITMStatusNone {
				require.Nil(t, state)
				return
			}
			require.NotNil(t, state)
			require.Equal(t, testCase.status, state.Status())
			require.Equal(t, testCase.reason, state.Reason())
		})
	}
}

func TestReloadKeepsAuthority(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), fileOptions(ca, true, []string{"a.test"}, nil))
	before := engine.config.Load().authority
	require.NotNil(t, before)
	fingerprint := engine.Status().AuthorityFingerprint
	require.NotEmpty(t, fingerprint)

	commit, err := engine.Reload(fileOptions(ca, true, []string{"b.test"}, nil))
	require.NoError(t, err)
	require.NotNil(t, engine.Decide(tlsMetadata("a.test", "10.0.0.1:443")), "reload applied before commit")
	commit()
	require.Same(t, before, engine.config.Load().authority)
	require.Nil(t, engine.Decide(tlsMetadata("a.test", "10.0.0.1:443")))
	require.NotNil(t, engine.Decide(tlsMetadata("b.test", "10.0.0.1:443")))

	commit, err = engine.Reload(fileOptions(ca, false, []string{"b.test"}, nil))
	require.NoError(t, err)
	commit()
	require.False(t, engine.Status().Enabled)
	require.Nil(t, engine.Decide(tlsMetadata("b.test", "10.0.0.1:443")))
	commit, err = engine.Reload(fileOptions(ca, true, []string{"b.test"}, nil))
	require.NoError(t, err)
	commit()
	require.Same(t, before, engine.config.Load().authority)

	other := writeTestCA(t)
	commit, err = engine.Reload(fileOptions(other, true, []string{"b.test"}, nil))
	require.NoError(t, err)
	commit()
	require.NotEqual(t, fingerprint, engine.Status().AuthorityFingerprint)
}

func TestReloadRejectsInvalid(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), fileOptions(ca, true, []string{"a.test"}, nil))
	invalid := []*option.MITMOptions{
		fileOptions(ca, true, []string{"*"}, nil),
		fileOptions(testCA{certificatePath: ca.certificatePath, keyPath: filepath.Join(t.TempDir(), "missing.key")}, true, []string{"a.test"}, nil),
		{Enabled: true, Certificate: &option.MITMCertificateOptions{Source: C.MITMCertificateSourceFile}},
		{Enabled: true, Certificate: &option.MITMCertificateOptions{Source: "keychain"}},
		{Enabled: true, Certificate: &option.MITMCertificateOptions{CertificatePath: ca.certificatePath, KeyPath: ca.keyPath}},
	}
	for _, options := range invalid {
		_, err := engine.Reload(options)
		require.Error(t, err)
	}
	require.NotNil(t, engine.Decide(tlsMetadata("a.test", "10.0.0.1:443")))
	_, err := NewEngine(context.Background(), log.NewNOPFactory().NewLogger("mitm"), invalid[0])
	require.Error(t, err)
}

func TestDecideMissDoesNotAllocate(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), fileOptions(ca, true, benchmarkHostnames(), []string{"skip.example.com"}))
	metadata := tlsMetadata("www.example.org", "10.0.0.1:443")
	other := tlsMetadata("www.example.org", "10.0.0.1:443")
	other.Protocol = C.ProtocolHTTP
	allocations := testing.AllocsPerRun(1000, func() {
		if engine.Decide(metadata) != nil || engine.Decide(other) != nil {
			t.Fatal("unexpected match")
		}
	})
	require.Zero(t, allocations)
	disabled := newTestEngine(t, context.Background(), nil)
	allocations = testing.AllocsPerRun(1000, func() {
		if disabled.Decide(metadata) != nil {
			t.Fatal("unexpected match")
		}
	})
	require.Zero(t, allocations)
}

func benchmarkHostnames() []string {
	hostnames := make([]string, 0, 100)
	for i := range 100 {
		hostnames = append(hostnames, "host"+string(rune('a'+i%26))+string(rune('a'+i/26))+".example.com")
	}
	return append(hostnames, "*.example.net")
}

func BenchmarkDecideMiss(b *testing.B) {
	ca := writeTestCA(b)
	engine := newTestEngine(b, context.Background(), fileOptions(ca, true, benchmarkHostnames(), []string{"skip.example.com"}))
	metadata := tlsMetadata("www.example.org", "10.0.0.1:443")
	b.ReportAllocs()
	for b.Loop() {
		if engine.Decide(metadata) != nil {
			b.Fatal("unexpected match")
		}
	}
}

func BenchmarkDecideDisabled(b *testing.B) {
	engine := newTestEngine(b, context.Background(), nil)
	metadata := tlsMetadata("www.example.org", "10.0.0.1:443")
	b.ReportAllocs()
	for b.Loop() {
		if engine.Decide(metadata) != nil {
			b.Fatal("unexpected match")
		}
	}
}

func BenchmarkDecideHit(b *testing.B) {
	ca := writeTestCA(b)
	engine := newTestEngine(b, context.Background(), fileOptions(ca, true, benchmarkHostnames(), []string{"skip.example.com"}))
	metadata := tlsMetadata("www.example.net", "10.0.0.1:443")
	b.ReportAllocs()
	for b.Loop() {
		if engine.Decide(metadata) == nil {
			b.Fatal("expected match")
		}
	}
}
