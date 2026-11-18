//go:build with_utls

package mitm

import (
	"context"
	"net"

	utls "github.com/metacubex/utls"
)

const (
	extensionPreSharedKey uint16 = 41
)

// mirroredClient returns an uTLS client whose ClientHello copies the client's
// (carried by ctx): cipher suites, extensions and their order, GREASE
// placement; the key shares are generated anew, the server name is the
// upstream one and the ALPN offer the protocols. nil means the hello cannot be
// mirrored and the configured fingerprint applies.
func (e *Engine) mirroredClient(ctx context.Context, conn net.Conn, config *utls.Config, protocols []string) *utls.UConn {
	record := clientHelloFrom(ctx)
	if record == nil {
		return nil
	}
	spec, err := mirrorSpec(record, protocols)
	if err != nil {
		e.logger.DebugContext(ctx, "mirror client hello: ", err)
		return nil
	}
	tlsConn := utls.UClient(conn, config, utls.HelloCustom)
	err = tlsConn.ApplyPreset(spec)
	if err != nil {
		e.logger.DebugContext(ctx, "mirror client hello: ", err)
		return nil
	}
	return tlsConn
}

// mirrorSpec turns a ClientHello record into a spec for the upstream hello.
// A pre-shared key (a session of the client with this proxy) means nothing to
// the upstream and is dropped.
func mirrorSpec(record []byte, protocols []string) (*utls.ClientHelloSpec, error) {
	fingerprinter := utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := fingerprinter.RawClientHello(record)
	if err != nil {
		return nil, err
	}
	ids, _ := helloExtensionIDs(record)
	kept := spec.Extensions[:0:0]
	for i, extension := range spec.Extensions {
		if i < len(ids) && ids[i] == extensionPreSharedKey {
			continue
		}
		if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
			alpnExtension.AlpnProtocols = protocols
		}
		kept = append(kept, extension)
	}
	spec.Extensions = kept
	return spec, nil
}
