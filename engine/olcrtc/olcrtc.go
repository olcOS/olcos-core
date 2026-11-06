// Package olcrtc adapts the existing olcrtc WebRTC transport to engine.Engine.
//
// Registration and profile validation only. The apps drive the olcrtc runtime
// directly through its gomobile package (olcrtc/mobile) and mobile/tunstack,
// so Start returns engine.ErrNotImplemented until that path moves behind the
// Engine interface. The olcrtc source itself lives in olcrtc/ (see
// docs/olcrtc.md).
package olcrtc

import (
	"context"
	"errors"

	"github.com/olcOS/olcos-core/engine"
)

// Engine implements engine.Engine for the olcrtc transport.
type Engine struct{}

func init() { engine.Register(Engine{}) }

// Kind reports engine.KindOlcrtc.
func (Engine) Kind() engine.Kind { return engine.KindOlcrtc }

// Start validates the profile and will start the olcrtc mobile runtime
// plus tunstack. The SOCKS listener is always local because the upstream
// core does not own the TUN device.
func (Engine) Start(ctx context.Context, p engine.Profile, h engine.Host) (engine.Session, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Host == "" || p.Room == "" {
		return nil, errors.New("olcrtc: carrier and room are required")
	}
	if h == nil {
		return nil, errors.New("olcrtc: nil host")
	}
	return nil, engine.ErrNotImplemented
}
