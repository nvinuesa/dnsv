package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"github.com/underscorenico/dnsv/internal/config"
)

type DNS struct {
	Query  string
	Answer net.IP
	Type   layers.DNSType
}

type DNSValidator struct {
	config config.Config
}

func NewDNSValidator(config config.Config) *DNSValidator {
	return &DNSValidator{
		config: config,
	}
}

func (v *DNSValidator) MainLoop() error {
	if handle, err := pcap.OpenLive(v.config.Device, 1600, true, time.Second); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(v.createBPFFilter()); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if dns := filterDNSPacket(packet); dns != nil {
				v.queryValidators(dns)
			}
		}
	}
	return nil
}

// createBPFFilter will create a correct bpf filter that ignores the
// response from the validators and therefore avoid looping on the same
// answers.
func (v *DNSValidator) createBPFFilter() string {
	var filter string
	for _, validator := range v.config.Validators {
		filter += fmt.Sprintf("src host not %s and ", validator)
	}
	return filter + "udp and port 53"
}

func filterDNSPacket(packet gopacket.Packet) *DNS {
	if dns := packet.Layer(layers.LayerTypeDNS).(*layers.DNS); dns != nil {
		if (dns.Questions[0].Type == layers.DNSTypeA ||
			dns.Questions[0].Type == layers.DNSTypeAAAA) &&
			len(dns.Answers) > 0 &&
			(dns.Answers[len(dns.Answers)-1].Type == layers.DNSTypeA ||
				dns.Answers[len(dns.Answers)-1].Type == layers.DNSTypeAAAA) {

			return &DNS{
				Query:  string(dns.Questions[0].Name),
				Answer: dns.Answers[len(dns.Answers)-1].IP,
				Type:   dns.Answers[len(dns.Answers)-1].Type,
			}
		}
	}
	return nil
}

func (v *DNSValidator) queryValidators(dns *DNS) error {
	logs := make(map[string]string)

	for _, validator := range v.config.Validators {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 10 * time.Second,
				}
				server := fmt.Sprintf("%s:53", validator)
				return d.DialContext(ctx, network, server)
			},
		}
		addrs, err := r.LookupHost(context.Background(), dns.Query)
		if err != nil {
			return errors.Wrapf(err, "error trying to request validator: '%s', query '%s'", validator, dns.Query)
		}
		if dns.Type == layers.DNSTypeA {
			if !net.ParseIP(addrs[len(addrs)-1]).Equal(dns.Answer) {
				logs[validator] = addrs[len(addrs)-1]
			}
		} else if dns.Type == layers.DNSTypeAAAA {
			if !net.ParseIP(addrs[0]).Equal(dns.Answer) {
				logs[validator] = addrs[0]
			}
		}
	}

	if len(logs) == len(v.config.Validators) {
		// log.Errorf("current dns answered %s for query %s, all validators answered differently: %v", dns.Answer.String(), dns.Query, logs)
		fmt.Println("error")
	} else if (len(logs)) > 0 {
		// log.Warnf("current dns answered %s for query %s, some validators answered differently: %v", dns.Answer.String(), dns.Query, logs)
		fmt.Println("warn")
	}
	fmt.Println("OK")

	return nil
}
