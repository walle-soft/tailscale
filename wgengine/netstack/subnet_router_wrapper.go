// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netstack

import (
	"tailscale.com/wgengine/router"
)

type subnetRouter struct {
	router.Router
}

// NewSubnetRouterWrapper returns a Router wrapper that prevents the
// underlying Router r from seeing any advertised subnet routes, as
// netstack will handle them instead.
func NewSubnetRouterWrapper(r router.Router) router.Router {
	return &subnetRouter{
		Router: r,
	}
}

func (r *subnetRouter) Set(c *router.Config) error {
	if c != nil {
		c.SubnetRoutes = nil // netstack will handle
	}
	return r.Router.Set(c)
}
