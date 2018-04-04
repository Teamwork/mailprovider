// Package mailprovider contains a list of common email providers.
package mailprovider

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"

	toml "github.com/pelletier/go-toml"
)

// Service constants.
const (
	ServiceSMTP = uint8(1)
	ServiceIMAP = uint8(2)
	ServicePOP3 = uint8(4)
)

// TLS constants.
const (
	SecurityNone     = uint8(1)
	SecurityTLS      = uint8(2)
	SecurityStartTLS = uint8(3) // STARTTLS (SMTP, IMAP) or STLS (POP3)
)

// Auth constants.
const (
	AuthAuto    = uint8(1)
	AuthPlain   = uint8(2)
	AuthLogin   = uint8(3)
	AuthCramMD5 = uint8(4)
)

// Service that we found.
type Service struct {
	Domains []string `toml:"domains"`
	Public  []string `toml:"public"`
	MX      []string `toml:"mx"`

	Name string `toml:"name"`

	SMTPHost     string `toml:"smtp_host"`
	SMTPPort     uint16 `toml:"smtp_port"`
	SMTPSecurity uint8  `toml:"smtp_security"`
	SMTPAuth     uint8  `toml:"smtp_auth"`

	IMAPHost     string `toml:"imap_host"`
	IMAPPort     uint16 `toml:"imap_port"`
	IMAPSecurity uint8  `toml:"imap_security"`
	IMAPAuth     uint8  `toml:"imap_auth"`

	POP3Host     string `toml:"pop3_host"`
	POP3Port     uint16 `toml:"pop3_port"`
	POP3Security uint8  `toml:"pop3_security"`
	POP3Auth     uint8  `toml:"pop3_auth"`
}

var (
	services     []*Service              // All known services.
	knownDomains = map[string]*Service{} // Access by domain.
	knownMX      = map[string]*Service{} // Access by MX record.
	knownPublic  = map[string]*Service{} // Domains with many users.
)

func init() {
	// TODO: perhaps also include a services.json file generated from the TOML
	// file? That way we don't have to rely on the go-toml library.
	f := "./services.toml"

	t, err := ioutil.ReadFile(f)
	if err != nil {
		panic(fmt.Sprintf("could not read %v: %v", f, err))
	}

	var s struct {
		Service []*Service `toml:"service"`
	}
	err = toml.Unmarshal(t, &s)
	if err != nil {
		panic(fmt.Sprintf("could not unmarshal %v: %v", f, err))
	}

	services = s.Service

	for _, s := range services {
		for _, d := range s.Domains {
			knownDomains[d] = s
		}
		for _, mx := range s.MX {
			knownMX[mx] = s
		}
		for _, p := range s.Public {
			knownPublic[p] = s
		}

		// No longer need this info, so clear it to save some memory.
		s.Public = nil
		s.MX = nil
		s.Domains = nil
	}
}

// Append data from another service, setting the values that aren't set yet.
func (s *Service) Append(s2 *Service) {
	if s.SMTPHost == "" {
		s.SMTPHost = s2.SMTPHost
	}
	if s.SMTPPort == 0 {
		s.SMTPPort = s2.SMTPPort
	}
	if s.SMTPSecurity == 0 {
		s.SMTPSecurity = s2.SMTPSecurity
	}
	if s.SMTPAuth == 0 {
		s.SMTPAuth = s2.SMTPAuth
	}

	if s.IMAPHost == "" {
		s.IMAPHost = s2.IMAPHost
	}
	if s.IMAPPort == 0 {
		s.IMAPPort = s2.IMAPPort
	}
	if s.IMAPSecurity == 0 {
		s.IMAPSecurity = s2.IMAPSecurity
	}
	if s.IMAPAuth == 0 {
		s.IMAPAuth = s2.IMAPAuth
	}

	if s.POP3Host == "" {
		s.POP3Host = s2.POP3Host
	}
	if s.POP3Port == 0 {
		s.POP3Port = s2.POP3Port
	}
	if s.POP3Security == 0 {
		s.POP3Security = s2.POP3Security
	}
	if s.POP3Auth == 0 {
		s.POP3Auth = s2.POP3Auth
	}
}

// Found reports if the server data for all of the given services is populated.
func (s *Service) Found(services uint8) bool {
	if services&ServiceSMTP != 0 && s.SMTPHost == "" {
		return false
	}
	if services&ServiceIMAP != 0 && s.IMAPHost == "" {
		return false
	}
	if services&ServicePOP3 != 0 && s.POP3Host == "" {
		return false
	}
	return true
}

// Public attempts to load a public domain.
func Public(domain string) *Service {
	return knownPublic[domain]
}

// Lookup the server settings for a domain. The domain is usually the domain
// part of the email (e.g. "example.com" in "martin@example.com").
func Lookup(domain string, services uint8) *Service {
	s := LookupKnown(domain)
	if !s.Found(services) {
		s.Append(LookupSRV(domain, services))
	}
	if !s.Found(services) {
		s.Append(LookupMX(domain))
	}
	return s
}

// LookupKnown attempts to look up the information from a list of widely used
// well-known providers. This saves some DNS lookups, as well as providing more
// detailed information.
func LookupKnown(domain string) *Service {
	return knownDomains[domain]
}

// LookupSRV looks up details using RFC 2782/6186 SRV records.
// https://tools.ietf.org/html/rfc2782
// https://tools.ietf.org/html/rfc6186
func LookupSRV(domain string, services uint8) *Service {
	var wg sync.WaitGroup
	s := &Service{}

	if services&ServiceSMTP != 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, addrs, _ := net.LookupSRV("submission", "tcp", domain)
			if len(addrs) > 0 {
				s.SMTPHost = strings.TrimRight(addrs[0].Target, ".")
				s.SMTPPort = addrs[0].Port
				s.SMTPSecurity = SecurityTLS
				if s.SMTPPort == 587 {
					s.SMTPSecurity = SecurityStartTLS
				}
			}
		}()
	}

	if services&ServiceIMAP != 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, addrs, _ := net.LookupSRV("imaps", "tcp", domain)
			if len(addrs) == 0 {
				_, addrs, _ = net.LookupSRV("imap", "tcp", domain)
			}
			if len(addrs) > 0 {
				s.IMAPHost = strings.TrimRight(addrs[0].Target, ".")
				s.IMAPPort = addrs[0].Port
				s.IMAPSecurity = SecurityStartTLS
				if s.IMAPPort == 993 {
					s.IMAPSecurity = SecurityTLS
				}
			}
		}()
	}

	if services&ServicePOP3 != 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, addrs, _ := net.LookupSRV("pop3s", "tcp", domain)
			if len(addrs) == 0 {
				_, addrs, _ = net.LookupSRV("pop3", "tcp", domain)
			}
			if len(addrs) > 0 {
				s.POP3Host = strings.TrimRight(addrs[0].Target, ".")
				s.POP3Port = addrs[0].Port
				s.POP3Security = SecurityStartTLS
				if s.POP3Port == 995 {
					s.POP3Security = SecurityTLS
				}
			}
		}()
	}

	wg.Wait()
	return s
}

// LookupMX attempts to find the services by looking at a list of known MX
// records.
func LookupMX(domain string) *Service {
	records, _ := net.LookupMX(domain)
	for _, r := range records {
		match, ok := knownMX[strings.TrimRight(r.Host, ".")]
		if ok {
			return match
		}
	}

	return nil
}
