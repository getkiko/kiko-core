package mitm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm/authority"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

type testIntermediate struct {
	chainPEM        []byte
	keyPKCS8        []byte
	rootFingerprint string
	notAfter        time.Time
	fingerprint     string
	root            *x509.Certificate
}

func issueTestIntermediate(t testing.TB) testIntermediate {
	t.Helper()
	rootPEM, rootKeyPEM, err := authority.Generate("Kiko Test Root", 365*24*time.Hour)
	require.NoError(t, err)
	chainPEM, keyPKCS8, err := authority.IssueIntermediate(rootPEM, rootKeyPEM, "Kiko Test Intermediate", authority.IntermediateValidity)
	require.NoError(t, err)
	rootBlock, _ := pem.Decode(rootPEM)
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	require.NoError(t, err)
	interBlock, _ := pem.Decode(chainPEM)
	intermediate, err := x509.ParseCertificate(interBlock.Bytes)
	require.NoError(t, err)
	rootSum := sha256.Sum256(root.Raw)
	interSum := sha256.Sum256(intermediate.Raw)
	return testIntermediate{
		chainPEM:        chainPEM,
		keyPKCS8:        keyPKCS8,
		rootFingerprint: hex.EncodeToString(rootSum[:]),
		notAfter:        intermediate.NotAfter,
		fingerprint:     hex.EncodeToString(interSum[:]),
		root:            root,
	}
}

func (i testIntermediate) push(engine *Engine) error {
	return engine.SetAuthority(i.chainPEM, i.keyPKCS8, i.rootFingerprint, i.notAfter)
}

func managedOptions(enabled bool, include []string) *option.MITMOptions {
	return &option.MITMOptions{
		Enabled:   enabled,
		Hostnames: &option.MITMHostnamesOptions{Include: include},
	}
}

func requireDecide(t *testing.T, engine *Engine, host string, status adapter.MITMStatus, reason string) {
	t.Helper()
	state := engine.Decide(tlsMetadata(host, "10.0.0.1:443"))
	require.NotNil(t, state)
	require.Equal(t, status, state.Status())
	require.Equal(t, reason, state.Reason())
}

func TestManagedAuthorityLifecycle(t *testing.T) {
	engine := newTestEngine(t, context.Background(), managedOptions(true, []string{"a.test"}))
	status := engine.Status()
	require.True(t, status.AuthorityPending)
	require.Equal(t, "managed", status.CertificateSource)
	requireDecide(t, engine, "a.test", adapter.MITMStatusSkipped, ReasonAuthorityPending)

	first := issueTestIntermediate(t)
	require.NoError(t, first.push(engine))
	requireDecide(t, engine, "a.test", adapter.MITMStatusPending, "")
	status = engine.Status()
	require.False(t, status.AuthorityPending)
	require.Equal(t, first.fingerprint, status.AuthorityFingerprint)
	require.Equal(t, first.rootFingerprint, status.RootFingerprint)
	require.Equal(t, first.notAfter.Unix(), status.AuthorityNotAfter.Unix())

	signer := engine.config.Load().authority
	cert, err := signer.Leaf("a.test", nil)
	require.NoError(t, err)
	require.Len(t, cert.Certificate, 2)
	require.Equal(t, 1, engine.Status().LeafCacheSize)

	// Rotation: a new intermediate under the same root starts with an empty cache.
	second := issueTestIntermediate(t)
	require.NoError(t, second.push(engine))
	status = engine.Status()
	require.NotEqual(t, first.fingerprint, status.AuthorityFingerprint)
	require.Equal(t, second.fingerprint, status.AuthorityFingerprint)
	require.Zero(t, status.LeafCacheSize)
	require.NotSame(t, signer, engine.config.Load().authority)
	// A session that started before keeps its authority.
	require.Equal(t, 1, signer.CacheLen())

	// An invalid push changes nothing.
	require.Error(t, engine.SetAuthority(first.chainPEM, second.keyPKCS8, first.rootFingerprint, first.notAfter))
	require.Error(t, engine.SetAuthority(first.chainPEM, nil, first.rootFingerprint, first.notAfter))
	require.Error(t, engine.SetAuthority(nil, first.keyPKCS8, "", time.Time{}))
	require.Equal(t, second.fingerprint, engine.Status().AuthorityFingerprint)

	require.NoError(t, engine.SetAuthority(nil, nil, "", time.Time{}))
	status = engine.Status()
	require.True(t, status.AuthorityPending)
	require.Empty(t, status.AuthorityFingerprint)
	require.Empty(t, status.RootFingerprint)
	require.True(t, status.AuthorityNotAfter.IsZero())
	requireDecide(t, engine, "a.test", adapter.MITMStatusSkipped, ReasonAuthorityPending)
}

func TestManagedAuthorityAcrossReload(t *testing.T) {
	ca := writeTestCA(t)
	engine := newTestEngine(t, context.Background(), managedOptions(false, []string{"a.test"}))
	managed := issueTestIntermediate(t)
	// Pushed while disabled, used once enabled.
	require.NoError(t, managed.push(engine))
	require.Nil(t, engine.Decide(tlsMetadata("a.test", "10.0.0.1:443")))

	commit, err := engine.Reload(managedOptions(true, []string{"a.test", "b.test"}))
	require.NoError(t, err)
	commit()
	requireDecide(t, engine, "b.test", adapter.MITMStatusPending, "")
	require.Equal(t, managed.fingerprint, engine.Status().AuthorityFingerprint)

	// The file source ignores the managed authority, which stays stored.
	commit, err = engine.Reload(fileOptions(ca, true, []string{"a.test"}, nil))
	require.NoError(t, err)
	commit()
	status := engine.Status()
	require.Equal(t, "file", status.CertificateSource)
	require.NotEqual(t, managed.fingerprint, status.AuthorityFingerprint)
	require.Equal(t, status.AuthorityFingerprint, status.RootFingerprint)
	fileFingerprint := status.AuthorityFingerprint
	rotated := issueTestIntermediate(t)
	require.NoError(t, rotated.push(engine))
	require.Equal(t, fileFingerprint, engine.Status().AuthorityFingerprint)

	commit, err = engine.Reload(managedOptions(true, []string{"a.test"}))
	require.NoError(t, err)
	commit()
	require.Equal(t, rotated.fingerprint, engine.Status().AuthorityFingerprint)
	requireDecide(t, engine, "a.test", adapter.MITMStatusPending, "")

	// A push between validation and commit is kept by the commit.
	commit, err = engine.Reload(managedOptions(true, []string{"b.test"}))
	require.NoError(t, err)
	require.NoError(t, engine.SetAuthority(nil, nil, "", time.Time{}))
	commit()
	requireDecide(t, engine, "b.test", adapter.MITMStatusSkipped, ReasonAuthorityPending)
	commit, err = engine.Reload(managedOptions(true, []string{"c.test"}))
	require.NoError(t, err)
	require.NoError(t, managed.push(engine))
	commit()
	requireDecide(t, engine, "c.test", adapter.MITMStatusPending, "")
	require.Equal(t, managed.fingerprint, engine.Status().AuthorityFingerprint)
}

func TestManagedAuthorityConcurrent(t *testing.T) {
	engine := newTestEngine(t, context.Background(), managedOptions(true, []string{"a.test"}))
	intermediates := []testIntermediate{issueTestIntermediate(t), issueTestIntermediate(t)}
	var wait sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wait.Go(func() {
			metadata := tlsMetadata("a.test", "10.0.0.1:443")
			for {
				select {
				case <-stop:
					return
				default:
				}
				if engine.Decide(metadata) == nil {
					t.Error("unexpected miss")
					return
				}
				_ = engine.Status()
			}
		})
	}
	wait.Go(func() {
		for i := range 100 {
			var err error
			if i%3 == 2 {
				err = engine.SetAuthority(nil, nil, "", time.Time{})
			} else {
				err = intermediates[i%2].push(engine)
			}
			if err != nil {
				t.Error(err)
			}
		}
	})
	wait.Go(func() {
		for range 100 {
			commit, err := engine.Reload(managedOptions(true, []string{"a.test"}))
			if err != nil {
				t.Error(err)
				return
			}
			commit()
		}
	})
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wait.Wait()
	// The last push wins once both writers are done.
	require.NoError(t, intermediates[0].push(engine))
	require.Equal(t, intermediates[0].fingerprint, engine.Status().AuthorityFingerprint)
}

func TestSetAuthorityLogsNoKeyMaterial(t *testing.T) {
	var output bytes.Buffer
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, &output, "", nil, false)
	require.NoError(t, factory.Start())
	defer factory.Close()
	engine, err := NewEngine(context.Background(), factory.NewLogger("mitm"), managedOptions(true, []string{"a.test"}))
	require.NoError(t, err)
	defer engine.Close()
	managed := issueTestIntermediate(t)
	require.NoError(t, managed.push(engine))
	err = engine.SetAuthority(managed.chainPEM, managed.keyPKCS8[:len(managed.keyPKCS8)-1], managed.rootFingerprint, managed.notAfter)
	require.Error(t, err)
	require.NotContains(t, err.Error(), string(managed.keyPKCS8))
	require.NoError(t, engine.SetAuthority(nil, nil, "", time.Time{}))
	content := output.Bytes()
	require.Contains(t, string(content), managed.fingerprint)
	require.Contains(t, string(content), "certificate authority cleared")
	require.False(t, bytes.Contains(content, managed.keyPKCS8))
	require.False(t, bytes.Contains(content, managed.chainPEM))
	require.NotContains(t, string(content), "PRIVATE KEY")
	require.NotContains(t, string(content), "BEGIN CERTIFICATE")
}

func TestSetAuthorityDisablesCoreDumps(t *testing.T) {
	var calls int
	original := setCoreLimit
	coreDumpOnce = sync.Once{}
	setCoreLimit = func() error {
		calls++
		return nil
	}
	t.Cleanup(func() {
		setCoreLimit = original
		coreDumpOnce = sync.Once{}
	})
	for _, options := range []*option.MITMOptions{nil, managedOptions(false, []string{"a.test"})} {
		engine := newTestEngine(t, context.Background(), options)
		require.NoError(t, engine.SetAuthority(nil, nil, "", time.Time{}))
		require.Zero(t, calls)
		require.NoError(t, issueTestIntermediate(t).push(engine))
		require.Equal(t, 1, calls)
		coreDumpOnce = sync.Once{}
		calls = 0
	}
}
