package route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// A connection sniffed by an earlier rule takes the sniffed domain as its
// destination when a later sniff rule asks for the override.
func TestSniffOverrideAfterEarlierSniff(t *testing.T) {
	router := &Router{ctx: context.Background(), logger: log.NewNOPFactory().Logger()}
	address := M.SocksaddrFrom(netip.MustParseAddr("203.0.113.7"), 443)
	sniffed := func() *adapter.InboundContext {
		return &adapter.InboundContext{Destination: address, Protocol: C.ProtocolTLS, Domain: "example.com"}
	}

	metadata := sniffed()
	_, _, err := router.actionSniff(context.Background(), metadata, &R.RuleActionSniff{OverrideDestination: true}, nil, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "example.com", metadata.Destination.Fqdn)
	require.Equal(t, uint16(443), metadata.Destination.Port)

	metadata = sniffed()
	_, _, err = router.actionSniff(context.Background(), metadata, &R.RuleActionSniff{}, nil, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, address, metadata.Destination, "a sniff without the override keeps the address")

	metadata = sniffed()
	metadata.Domain = ""
	_, _, err = router.actionSniff(context.Background(), metadata, &R.RuleActionSniff{OverrideDestination: true}, nil, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, address, metadata.Destination, "no sniffed domain, nothing to override with")
}
