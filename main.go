package listencaddy

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(ListenCaddy{})
	httpcaddyfile.RegisterHandlerDirective("listencaddy", parseCaddyfile)
}

type ListenCaddy struct {
	APIKey     string `json:"apikey,omitempty"`
	BannedURIs string `json:"banned_uris,omitempty"`
}

func (ListenCaddy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.listencaddy",
		New: func() caddy.Module { return new(ListenCaddy) },
	}
}

func (l *ListenCaddy) Provision(ctx caddy.Context) error {
	switch l.APIKey {
	case "":
		return fmt.Errorf("Missing API Key from AbuseIPDB. Check your Caddyfile and read the docs.")
	default:
		return nil
	}
}

func (l *ListenCaddy) Validate() error {
	if l.APIKey == "" {
		return fmt.Errorf("Missing API Key from AbuseIPDB. Check your Caddyfile and read the docs.")
	}
	if l.BannedURIs == "" {
		return fmt.Errorf("Can't find any banned URIs/paths. Check your Caddyfile and read the docs.")
	}
	return nil
}

func (l ListenCaddy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if strings.Contains(r.URL.Path, l.BannedURIs) {
		report(r.RemoteAddr)
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (l *ListenCaddy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&l.APIKey, &l.BannedURIs) {
			return d.ArgErr()
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var l ListenCaddy
	err := l.UnmarshalCaddyfile(h.Dispenser)
	return l, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*ListenCaddy)(nil)
	_ caddy.Validator             = (*ListenCaddy)(nil)
	_ caddyhttp.MiddlewareHandler = (*ListenCaddy)(nil)
	_ caddyfile.Unmarshaler       = (*ListenCaddy)(nil)
)

func report(ip string) (l *ListenCaddy) {
	fmt.Println("Reporting IP: " + ip)

	jsonBody := []byte(`{"ip": "` + ip + `", "categories": ["18"], "comment": "IP accessed a banned URI/Path (ListenCaddy)"}`)
	bodyReader := bytes.NewReader(jsonBody)

	requestURL := fmt.Sprintf("https://api.abuseipdb.com/api/v2/report")
	req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	req.Header.Set("Key", l.APIKey)
	req.Header.Set("Accept", "application/json")
	defer req.Body.Close()

	return nil
}
