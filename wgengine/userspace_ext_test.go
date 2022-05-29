// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine_test

import (
	"testing"

	"golang.zx2c4.com/wireguard/tun"
	"tailscale.com/ipn/node"
	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

func TestIsNetstack(t *testing.T) {
	parts := new(node.Parts)
	e, err := wgengine.NewUserspaceEngine(t.Logf, wgengine.Config{SetPart: parts.SetPart})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if !parts.IsNetstack() {
		t.Errorf("IsNetstack = false; want true")
	}
}

func TestIsNetstackRouter(t *testing.T) {
	tests := []struct {
		name              string
		conf              wgengine.Config
		setNetstackRouter bool
		want              bool
	}{
		{
			name: "no_netstack",
			conf: wgengine.Config{
				Tun:    newFakeOSTUN(),
				Router: newFakeOSRouter(),
			},
			want: false,
		},
		{
			name: "netstack",
			conf: wgengine.Config{},
			want: true,
		},
		{
			name: "hybrid_netstack",
			conf: wgengine.Config{
				Tun:    newFakeOSTUN(),
				Router: netstack.NewSubnetRouterWrapper(newFakeOSRouter()),
			},
			setNetstackRouter: true,
			want:              true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := new(node.Parts)
			if tt.setNetstackRouter {
				parts.NetstackRouter.Set(true)
			}
			conf := tt.conf
			conf.SetPart = parts.SetPart
			e, err := wgengine.NewUserspaceEngine(logger.Discard, conf)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if got := parts.IsNetstackRouter(); got != tt.want {
				t.Errorf("IsNetstackRouter = %v; want %v", got, tt.want)
			}
		})
	}
}

func newFakeOSRouter() router.Router {
	return someRandoOSRouter{router.NewFake(logger.Discard)}
}

type someRandoOSRouter struct {
	router.Router
}

func newFakeOSTUN() tun.Device {
	return someRandoOSTUN{tstun.NewFake()}
}

type someRandoOSTUN struct {
	tun.Device
}

// Name returns something that is not FakeTUN.
func (t someRandoOSTUN) Name() (string, error) { return "some_os_tun0", nil }
