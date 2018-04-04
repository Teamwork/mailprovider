package mailprovider

import (
	"fmt"
	"testing"

	"github.com/teamwork/test/diff"
)

func TestFound(t *testing.T) {
	cases := []struct {
		in       *Service
		services uint8
		want     bool
	}{
		{&Service{}, ServiceIMAP, false},
		{&Service{IMAPHost: "X"}, ServiceIMAP, true},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			out := tc.in.Found(tc.services)
			if out != tc.want {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
		})
	}
}

func TestAppend(t *testing.T) {
	cases := []struct {
		in, append, want *Service
	}{
		{&Service{}, &Service{}, &Service{}},
		{&Service{}, &Service{SMTPHost: "xx"}, &Service{SMTPHost: "xx"}},
		{&Service{SMTPHost: "set"}, &Service{SMTPHost: "xx"}, &Service{SMTPHost: "set"}},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			tc.in.Append(tc.append)
			if d := diff.Diff(tc.want, tc.in); d != "" {
				t.Errorf("\n%v", d)
			}
		})
	}
}

func TestLookupKnown(t *testing.T) {
	cases := []struct {
		in   string
		want *Service
	}{
		{"rwxrwxrwx.net", nil},
		{"gmail.com", &Service{
			Name:     "Gmail",
			SMTPHost: "smtp.gmail.com", SMTPPort: 587, SMTPSecurity: SecurityStartTLS, SMTPAuth: AuthLogin,
			IMAPHost: "imap.gmail.com", IMAPPort: 993, IMAPSecurity: SecurityTLS,
			POP3Host: "pop.gmail.com", POP3Port: 995, POP3Security: SecurityTLS,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			out := LookupKnown(tc.in)
			if d := diff.Diff(tc.want, out); d != "" {
				t.Errorf("\n%v", d)
			}
		})
	}
}

func TestLookupRFC6186(t *testing.T) {
	cases := []struct {
		in       string
		services uint8
		want     *Service
	}{
		{"rwxrwxrwx.net", ServiceIMAP | ServicePOP3 | ServiceSMTP, &Service{}},
		{"fastmail.com", ServiceSMTP, &Service{
			SMTPHost: "smtp.fastmail.com", SMTPPort: 587, SMTPSecurity: SecurityStartTLS,
		}},
		{"gmail.com", ServiceIMAP | ServicePOP3 | ServiceSMTP, &Service{
			//Name:     "Gmail",
			SMTPHost: "smtp.gmail.com", SMTPPort: 587, SMTPSecurity: SecurityStartTLS,
			IMAPHost: "imap.gmail.com", IMAPPort: 993, IMAPSecurity: SecurityTLS,
			POP3Host: "pop.gmail.com", POP3Port: 995, POP3Security: SecurityTLS,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			out := LookupSRV(tc.in, tc.services)
			if d := diff.Diff(tc.want, out); d != "" {
				t.Errorf("\n%v", d)
			}
		})
	}
}

func TestLookupMX(t *testing.T) {
	cases := []struct {
		in   string
		want *Service
	}{
		{"rwxrwxrwx.net", nil},
		{"gmail.com", &Service{
			Name:     "Gmail",
			SMTPHost: "smtp.gmail.com", SMTPPort: 587, SMTPSecurity: SecurityStartTLS, SMTPAuth: AuthLogin,
			IMAPHost: "imap.gmail.com", IMAPPort: 993, IMAPSecurity: SecurityTLS,
			POP3Host: "pop.gmail.com", POP3Port: 995, POP3Security: SecurityTLS,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			out := LookupMX(tc.in)
			if d := diff.Diff(tc.want, out); d != "" {
				t.Errorf("\n%v", d)
			}
		})
	}
}
