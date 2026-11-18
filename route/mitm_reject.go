package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
)

// rejectHost refuses a connection to a host that a mitm.http_rewrite reject
// rule covers entirely, when the connection is not decrypted (and so no
// request could be answered inside it). It goes the way of a reject rule
// action. A miss costs a few comparisons.
func (r *Router) rejectHost(ctx context.Context, metadata *adapter.InboundContext, rule adapter.Rule, buffers []*buf.Buffer) error {
	if metadata.Domain == "" || metadata.MITM.Serves() {
		return nil
	}
	if metadata.Protocol != C.ProtocolTLS && metadata.Destination.Port != 443 {
		return nil
	}
	rejecter, ok := r.mitm.(adapter.MITMHostRejecter)
	if !ok {
		return nil
	}
	id, reject := rejecter.RejectHost(metadata)
	if !reject {
		return nil
	}
	buf.ReleaseMulti(buffers)
	r.logger.InfoContext(ctx, "rewrite: reject ", metadata.Domain, " (", id, ")")
	r.trackRejected(ctx, *metadata, rule)
	return &R.RejectedError{Cause: R.ErrReset}
}
