package config

import (
	"fmt"
	"net"
)

type Config struct {
	Validators []string
	Device     string
}

func (c Config) ParseIPAddr() ([]net.IP, error) {
	ips := make([]net.IP, len(c.Validators))
	for i, st := range c.Validators {
		ips[i] = net.ParseIP(st)
		if ips[i] == nil {
			return nil, fmt.Errorf("malformed ip address: %s", st)
		}
	}
	return ips, nil
}
