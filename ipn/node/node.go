// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package node contains a Parts type containing all the subsystems a Tailscale
// node (tailscaled or platform equivalent).
//
// This package depends on nearly all parts of Tailscale, so it should not be
// imported by (or thus passed to) any package that does not want to depend on
// the world. In practice this means that only things like cmd/tailscaled,
// ipn/ipnlocal, and ipn/ipnserver should import this package.
package node

import (
	"fmt"
	"reflect"

	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/router"
)

// Parts are the Tailscale node's various subsystems.
type Parts struct {
	Dialer         Part[*tsdial.Dialer]
	DNSManager     Part[*dns.Manager] // can get its *resolver.Resolver from DNSManager.Resolver
	Engine         Part[wgengine.Engine]
	LinkMonitor    Part[*monitor.Mon]
	MagicSock      Part[*magicsock.Conn]
	NetstackRouter Part[bool] // using Netstack at all (either entirely or at least for subnets)
	Router         Part[router.Router]
	Tun            Part[*tstun.Wrapper]
	StateStore     Part[ipn.StateStore]
}

func (s *Parts) SetPart(v any) {
	switch v := v.(type) {
	case *monitor.Mon:
		s.LinkMonitor.Set(v)
	case *dns.Manager:
		s.DNSManager.Set(v)
	case *tsdial.Dialer:
		s.Dialer.Set(v)
	case wgengine.Engine:
		s.Engine.Set(v)
	case router.Router:
		s.Router.Set(v)
	case *tstun.Wrapper:
		s.Tun.Set(v)
	case *magicsock.Conn:
		s.MagicSock.Set(v)
	case ipn.StateStore:
		s.StateStore.Set(v)
	default:
		panic(fmt.Sprintf("unknown type %T", v))
	}
}

// IsNetstackRouter reports whether Tailscale is either fully netstack based
// (without TUN) or is at least using netstack for routing.
func (s *Parts) IsNetstackRouter() bool {
	if v, ok := s.NetstackRouter.GetOK(); ok {
		return v
	}
	return s.IsNetstack()
}

// IsNetstack reports whether Tailscale is running as a netstack-based TUN-free engine.
func (s *Parts) IsNetstack() bool {
	name, _ := s.Tun.Get().Name()
	return name == "FakeTUN"
}

// Part represents some part (some subsystem) of the Tailscale node sofware.
//
// A part can be set to a value, and then later retrieved. A part tracks whether
// it's been set and, once set, doesn't allow the value to change.
type Part[T any] struct {
	set bool
	v   T
}

// Set sets p to v.
//
// It panics if p is already set to a different value.
//
// Set must not be called concurrently with other Sets or Gets.
func (p *Part[T]) Set(v T) {
	if p.set {
		var oldVal any = p.v
		var newVal any = v
		if oldVal == newVal {
			// Allow setting to the same value.
			// Note we had to box them through "any" to force them to be comparable.
			// We can't set the type constraint T to be "comparable" because the interfaces
			// aren't comparable. (See https://github.com/golang/go/issues/52531 and
			// https://github.com/golang/go/issues/52614 for some background)
			return
		}

		var z *T
		panic(fmt.Sprintf("%v is already set", reflect.TypeOf(z).Elem().String()))
	}
	p.v = v
	p.set = true
}

// Get returns the value of p, panicking if it it hasn't been set.
func (p *Part[T]) Get() T {
	if !p.set {
		var z *T
		panic(fmt.Sprintf("%v is not set", reflect.TypeOf(z).Elem().String()))
	}
	return p.v
}

// GetOK returns the value of p (if any) and whether it's been set.
func (p *Part[T]) GetOK() (_ T, ok bool) {
	return p.v, p.set
}
