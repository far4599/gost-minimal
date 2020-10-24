package config

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/go-log/log"

	"github.com/far4599/gost-minimal"
)

type StringList []string

func (l *StringList) String() string {
	return fmt.Sprintf("%s", *l)
}
func (l *StringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

type Route struct {
	ServeNodes StringList
	ChainNodes StringList
	Retries    int
}

func (r *Route) ParseChain() (*gost.Chain, error) {
	chain := gost.NewChain()
	chain.Retries = r.Retries
	gid := 1 // Group ID

	for _, ns := range r.ChainNodes {
		ngroup := gost.NewNodeGroup()
		ngroup.ID = gid
		gid++

		// parse the base nodes
		nodes, err := ParseChainNode(ns)
		if err != nil {
			return nil, err
		}

		nid := 1 // Node ID
		for i := range nodes {
			nodes[i].ID = nid
			nid++
		}
		ngroup.AddNode(nodes...)

		ngroup.SetSelector(nil,
			gost.WithFilter(
				&gost.FailFilter{
					MaxFails:    nodes[0].GetInt("max_fails"),
					FailTimeout: nodes[0].GetDuration("fail_timeout"),
				},
				&gost.InvalidFilter{},
			),
			gost.WithStrategy(gost.NewStrategy(nodes[0].Get("strategy"))),
		)

		if cfg := nodes[0].Get("peer"); cfg != "" {
			f, err := os.Open(cfg)
			if err != nil {
				return nil, err
			}

			peerCfg := newPeerConfig()
			peerCfg.Group = ngroup
			peerCfg.BaseNodes = nodes
			peerCfg.Reload(f)
			f.Close()

			go gost.PeriodReload(peerCfg, cfg)
		}

		chain.AddNodeGroup(ngroup)
	}

	return chain, nil
}

func ParseChainNode(ns string) (nodes []gost.Node, err error) {
	node, err := gost.ParseNode(ns)
	if err != nil {
		return
	}

	if auth := node.Get("auth"); auth != "" && node.User == nil {
		c, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			return nil, err
		}
		cs := string(c)
		s := strings.IndexByte(cs, ':')
		if s < 0 {
			node.User = url.User(cs)
		} else {
			node.User = url.UserPassword(cs[:s], cs[s+1:])
		}
	}
	if node.User == nil {
		users, err := ParseUsers(node.Get("secrets"))
		if err != nil {
			return nil, err
		}
		if len(users) > 0 {
			node.User = users[0]
		}
	}

	serverName, sport, _ := net.SplitHostPort(node.Addr)
	if serverName == "" {
		serverName = "localhost" // default Server name
	}

	rootCAs, err := LoadCA(node.Get("ca"))
	if err != nil {
		return
	}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !node.GetBool("secure"),
		RootCAs:            rootCAs,
	}
	timeout := node.GetDuration("timeout")

	var host string

	var tr gost.Transporter
	switch node.Transport {
	case "tls":
		tr = gost.TLSTransporter()
	case "mtls":
		tr = gost.MTLSTransporter()
	case "ohttp":
		host = node.Get("host")
	default:
		tr = gost.TCPTransporter()
	}

	var connector gost.Connector
	switch node.Protocol {
	case "socks", "socks5":
		connector = gost.SOCKS5Connector(node.User)
	case "socks4":
		connector = gost.SOCKS4Connector()
	case "socks4a":
		connector = gost.SOCKS4AConnector()
	case "forward":
		connector = gost.ForwardConnector()
	case "sni":
		connector = gost.SNIConnector(node.Get("host"))
	case "http":
		connector = gost.HTTPConnector(node.User)
	default:
		connector = gost.AutoConnector(node.User)
	}

	node.DialOptions = append(node.DialOptions,
		gost.TimeoutDialOption(timeout),
	)

	node.ConnectOptions = []gost.ConnectOption{
		gost.UserAgentConnectOption(node.Get("agent")),
		gost.NoTLSConnectOption(node.GetBool("notls")),
	}

	if host == "" {
		host = node.Host
	}
	handshakeOptions := []gost.HandshakeOption{
		gost.AddrHandshakeOption(node.Addr),
		gost.HostHandshakeOption(host),
		gost.UserHandshakeOption(node.User),
		gost.TLSConfigHandshakeOption(tlsCfg),
		gost.IntervalHandshakeOption(node.GetDuration("ping")),
		gost.TimeoutHandshakeOption(timeout),
		gost.RetryHandshakeOption(node.GetInt("retry")),
	}
	node.Client = &gost.Client{
		Connector:   connector,
		Transporter: tr,
	}

	node.Bypass = ParseBypass(node.Get("bypass"))

	ips := ParseIP(node.Get("ip"), sport)
	for _, ip := range ips {
		nd := node.Clone()
		nd.Addr = ip
		// override the default Node address
		nd.HandshakeOptions = append(handshakeOptions, gost.AddrHandshakeOption(ip))
		// One Node per IP
		nodes = append(nodes, nd)
	}
	if len(ips) == 0 {
		node.HandshakeOptions = handshakeOptions
		nodes = []gost.Node{node}
	}

	return
}

func (r *Route) GenRouters() ([]Router, error) {
	chain, err := r.ParseChain()
	if err != nil {
		return nil, err
	}

	var rts []Router

	for _, ns := range r.ServeNodes {
		node, err := gost.ParseNode(ns)
		if err != nil {
			return nil, err
		}

		if auth := node.Get("auth"); auth != "" && node.User == nil {
			c, err := base64.StdEncoding.DecodeString(auth)
			if err != nil {
				return nil, err
			}
			cs := string(c)
			s := strings.IndexByte(cs, ':')
			if s < 0 {
				node.User = url.User(cs)
			} else {
				node.User = url.UserPassword(cs[:s], cs[s+1:])
			}
		}
		authenticator, err := ParseAuthenticator(node.Get("secrets"))
		if err != nil {
			return nil, err
		}
		if authenticator == nil && node.User != nil {
			kvs := make(map[string]string)
			kvs[node.User.Username()], _ = node.User.Password()
			authenticator = gost.NewLocalAuthenticator(kvs)
		}
		if node.User == nil {
			if users, _ := ParseUsers(node.Get("secrets")); len(users) > 0 {
				node.User = users[0]
			}
		}
		certFile, keyFile := node.Get("cert"), node.Get("key")
		tlsCfg, err := TlsConfig(certFile, keyFile)
		if err != nil && certFile != "" && keyFile != "" {
			return nil, err
		}

		ttl := node.GetDuration("ttl")
		timeout := node.GetDuration("timeout")

		var ln gost.Listener
		switch node.Transport {
		case "tls":
			ln, err = gost.TLSListener(node.Addr, tlsCfg)
		case "mtls":
			ln, err = gost.MTLSListener(node.Addr, tlsCfg)
		case "tcp":
			ln, err = gost.TCPListener(node.Addr)
		case "rtcp":
			ln, err = gost.TCPRemoteForwardListener(node.Addr, chain)
		case "dns":
			ln, err = gost.DNSListener(
				node.Addr,
				&gost.DNSOptions{
					Mode:      node.Get("mode"),
					TLSConfig: tlsCfg,
				},
			)
		default:
			ln, err = gost.TCPListener(node.Addr)
		}
		if err != nil {
			return nil, err
		}

		var handler gost.Handler
		switch node.Protocol {
		case "socks", "socks5":
			handler = gost.SOCKS5Handler()
		case "socks4", "socks4a":
			handler = gost.SOCKS4Handler()
		case "http":
			handler = gost.HTTPHandler()
		case "tcp":
			handler = gost.TCPDirectForwardHandler(node.Remote)
		case "rtcp":
			handler = gost.TCPRemoteForwardHandler(node.Remote)
		case "udp":
			handler = gost.UDPDirectForwardHandler(node.Remote)
		case "rudp":
			handler = gost.UDPRemoteForwardHandler(node.Remote)
		case "sni":
			handler = gost.SNIHandler()
		case "dns":
			handler = gost.DNSHandler(node.Remote)
		default:
			// start from 2.5, if remote is not empty, then we assume that it is a forward tunnel.
			if node.Remote != "" {
				handler = gost.TCPDirectForwardHandler(node.Remote)
			} else {
				handler = gost.AutoHandler()
			}
		}

		var whitelist, blacklist *gost.Permissions
		if node.Values.Get("whitelist") != "" {
			if whitelist, err = gost.ParsePermissions(node.Get("whitelist")); err != nil {
				return nil, err
			}
		}
		if node.Values.Get("blacklist") != "" {
			if blacklist, err = gost.ParsePermissions(node.Get("blacklist")); err != nil {
				return nil, err
			}
		}

		node.Bypass = ParseBypass(node.Get("bypass"))
		hosts := ParseHosts(node.Get("Hosts"))
		ips := ParseIP(node.Get("ip"), "")

		resolver := ParseResolver(node.Get("dns"))
		if resolver != nil {
			resolver.Init(
				gost.ChainResolverOption(chain),
				gost.TimeoutResolverOption(timeout),
				gost.TTLResolverOption(ttl),
				gost.PreferResolverOption(node.Get("prefer")),
				gost.SrcIPResolverOption(net.ParseIP(node.Get("ip"))),
			)
		}

		handler.Init(
			gost.AddrHandlerOption(ln.Addr().String()),
			gost.ChainHandlerOption(chain),
			gost.UsersHandlerOption(node.User),
			gost.AuthenticatorHandlerOption(authenticator),
			gost.TLSConfigHandlerOption(tlsCfg),
			gost.WhitelistHandlerOption(whitelist),
			gost.BlacklistHandlerOption(blacklist),
			gost.StrategyHandlerOption(gost.NewStrategy(node.Get("strategy"))),
			gost.MaxFailsHandlerOption(node.GetInt("max_fails")),
			gost.FailTimeoutHandlerOption(node.GetDuration("fail_timeout")),
			gost.BypassHandlerOption(node.Bypass),
			gost.ResolverHandlerOption(resolver),
			gost.HostsHandlerOption(hosts),
			gost.RetryHandlerOption(node.GetInt("retry")), // override the global retry option.
			gost.TimeoutHandlerOption(timeout),
			gost.ProbeResistHandlerOption(node.Get("probe_resist")),
			gost.KnockingHandlerOption(node.Get("knock")),
			gost.NodeHandlerOption(node),
			gost.IPsHandlerOption(ips),
			gost.TCPModeHandlerOption(node.GetBool("tcp")),
		)

		rt := Router{
			Node:     node,
			Server:   &gost.Server{Listener: ln},
			Handler:  handler,
			Chain:    chain,
			Resolver: resolver,
			Hosts:    hosts,
		}
		rts = append(rts, rt)
	}

	return rts, nil
}

type Router struct {
	Node     gost.Node
	Server   *gost.Server
	Handler  gost.Handler
	Chain    *gost.Chain
	Resolver gost.Resolver
	Hosts    *gost.Hosts
}

func (r *Router) Serve() error {
	log.Logf("%s on %s", r.Node.String(), r.Server.Addr())
	return r.Server.Serve(r.Handler)
}

func (r *Router) Close() error {
	if r == nil || r.Server == nil {
		return nil
	}
	return r.Server.Close()
}
