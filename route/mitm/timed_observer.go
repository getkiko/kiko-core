package mitm

import (
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/mitm/flow"
)

// timedObserver reports the connection setup durations on the first exchange
// of a connection; later exchanges reuse the connection and report none.
type timedObserver struct {
	flow.Observer
	connect time.Duration
	tls     time.Duration
	used    atomic.Bool
}

func (o *timedObserver) NewExchange(connection *flow.ConnectionInfo) flow.Exchange {
	exchange := o.Observer.NewExchange(connection)
	if o.used.CompareAndSwap(false, true) {
		exchange.SetDurations(0, o.connect, o.tls)
	}
	return exchange
}
