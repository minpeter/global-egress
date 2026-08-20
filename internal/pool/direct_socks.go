package pool

import (
	"net"

	"github.com/minpeter/global-egress/internal/socksdial"
)

func (p *Pool) dialerForDirectSocks(state *slotState) Dialer {
	return &socksdial.Dialer{
		Base:      &net.Dialer{},
		ProxyAddr: state.spec.SocksAddr,
		Username:  state.spec.socksUsername,
		Password:  state.spec.socksPassword,
		Timeout:   p.opts.HandshakeTimeout,
	}
}
