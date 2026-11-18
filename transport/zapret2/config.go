package zapret2

import (
	"errors"
	"fmt"
	"strings"
)

var ErrUnsupported = errors.New("zapret2 requires a Windows amd64 build with with_zapret2")

// Option is the configuration for one freedom outbound. The ordered strategy
// arguments use upstream zapret2 syntax. Capture ports limit which sockets
// are attached to the engine, independently of the upstream profile filters.
type Option struct {
	TCPPorts []int    `proxy:"tcp-ports,omitempty"`
	UDPPorts []int    `proxy:"udp-ports,omitempty"`
	Options  []string `proxy:"options"`
}

type config struct {
	tcp, udp map[uint16]bool
	args     []string
}

func parse(o *Option) (*config, error) {
	if o == nil {
		return nil, errors.New("missing zapret2 configuration")
	}
	tcp, err := parsePorts(o.TCPPorts)
	if err != nil {
		return nil, fmt.Errorf("tcp-ports: %w", err)
	}
	udp, err := parsePorts(o.UDPPorts)
	if err != nil {
		return nil, fmt.Errorf("udp-ports: %w", err)
	}
	if len(tcp)+len(udp) == 0 {
		return nil, errors.New("specify at least one tcp-ports or udp-ports entry")
	}
	if len(o.Options) > 128 {
		return nil, errors.New("too many strategy options")
	}
	args := []string{"zapret2", "--lua-init=@/lua/zapret-lib.lua", "--lua-init=@/lua/zapret-antidpi.lua", "--lua-init=@/lua/zapret-auto.lua"}
	var size int
	hasStrategy := false
	for i, arg := range o.Options {
		size += len(arg)
		if size > 64*1024 || strings.ContainsRune(arg, 0) {
			return nil, fmt.Errorf("option %d exceeds the supported size or contains NUL", i+1)
		}
		key, value, hasValue := strings.Cut(arg, "=")
		switch key {
		case "--new", "--name", "--template", "--import",
			"--filter-l3", "--filter-tcp", "--filter-udp", "--filter-l7",
			"--hostlist-domains", "--hostlist-exclude-domains", "--ipset-ip", "--ipset-exclude-ip",
			"--payload", "--in-range", "--out-range", "--blob", "--lua-init", "--lua-desync":
		default:
			return nil, fmt.Errorf("option %d: unsupported embedded strategy option %q", i+1, key)
		}
		if key != "--new" && key != "--template" && (!hasValue || value == "") {
			return nil, fmt.Errorf("option %d: %s needs a value", i+1, key)
		}
		hasStrategy = hasStrategy || key == "--lua-desync"
		args = append(args, arg)
	}
	if !hasStrategy {
		return nil, errors.New("specify at least one --lua-desync")
	}
	return &config{tcp: tcp, udp: udp, args: args}, nil
}

func parsePorts(ports []int) (map[uint16]bool, error) {
	m := make(map[uint16]bool, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %d", port)
		}
		m[uint16(port)] = true
	}
	return m, nil
}
