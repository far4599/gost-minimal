package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/far4599/gost-minimal"
)

type PeerConfig struct {
	Strategy    string `json:"strategy"`
	MaxFails    int    `json:"max_fails"`
	FailTimeout time.Duration
	PeriodF     time.Duration // the PeriodF for live reloading
	Nodes       []string      `json:"nodes"`
	Group       *gost.NodeGroup
	BaseNodes   []gost.Node
	StoppedF    chan struct{}
}

func newPeerConfig() *PeerConfig {
	return &PeerConfig{
		StoppedF: make(chan struct{}),
	}
}

func (cfg *PeerConfig) Validate() {
}

func (cfg *PeerConfig) Reload(r io.Reader) error {
	if cfg.Stopped() {
		return nil
	}

	if err := cfg.parse(r); err != nil {
		return err
	}
	cfg.Validate()

	group := cfg.Group
	group.SetSelector(
		nil,
		gost.WithFilter(
			&gost.FailFilter{
				MaxFails:    cfg.MaxFails,
				FailTimeout: cfg.FailTimeout,
			},
			&gost.InvalidFilter{},
		),
		gost.WithStrategy(gost.NewStrategy(cfg.Strategy)),
	)

	gNodes := cfg.BaseNodes
	nid := len(gNodes) + 1
	for _, s := range cfg.Nodes {
		nodes, err := ParseChainNode(s)
		if err != nil {
			return err
		}

		for i := range nodes {
			nodes[i].ID = nid
			nid++
		}

		gNodes = append(gNodes, nodes...)
	}

	nodes := group.SetNodes(gNodes...)
	for _, node := range nodes[len(cfg.BaseNodes):] {
		if node.Bypass != nil {
			node.Bypass.Stop() // clear the old nodes
		}
	}

	return nil
}

func (cfg *PeerConfig) parse(r io.Reader) error {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	// compatible with JSON format
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(cfg); err == nil {
		return nil
	}

	split := func(line string) []string {
		if line == "" {
			return nil
		}
		if n := strings.IndexByte(line, '#'); n >= 0 {
			line = line[:n]
		}
		line = strings.Replace(line, "\t", " ", -1)
		line = strings.TrimSpace(line)

		var ss []string
		for _, s := range strings.Split(line, " ") {
			if s = strings.TrimSpace(s); s != "" {
				ss = append(ss, s)
			}
		}
		return ss
	}

	cfg.Nodes = nil
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		ss := split(line)
		if len(ss) < 2 {
			continue
		}

		switch ss[0] {
		case "strategy":
			cfg.Strategy = ss[1]
		case "max_fails":
			cfg.MaxFails, _ = strconv.Atoi(ss[1])
		case "fail_timeout":
			cfg.FailTimeout, _ = time.ParseDuration(ss[1])
		case "reload":
			cfg.PeriodF, _ = time.ParseDuration(ss[1])
		case "peer":
			cfg.Nodes = append(cfg.Nodes, ss[1])
		}
	}

	return scanner.Err()
}

func (cfg *PeerConfig) Period() time.Duration {
	if cfg.Stopped() {
		return -1
	}
	return cfg.PeriodF
}

// Stop stops reloading.
func (cfg *PeerConfig) Stop() {
	select {
	case <-cfg.StoppedF:
	default:
		close(cfg.StoppedF)
	}
}

// Stopped checks whether the reloader is StoppedF.
func (cfg *PeerConfig) Stopped() bool {
	select {
	case <-cfg.StoppedF:
		return true
	default:
		return false
	}
}
