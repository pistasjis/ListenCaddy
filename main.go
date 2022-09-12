package listencaddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
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
	match, _ := regexp.MatchString(l.BannedURIs, r.URL.Path)

	if match {
		fmt.Println("Banned URI/Path accessed: " + r.URL.Path)
		split := strings.Split(r.RemoteAddr, ":")
		report(split[0])
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (l *ListenCaddy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "api_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				l.APIKey = d.Val()
			case "banned_uris":
				if !d.NextArg() {
					return d.ArgErr()
				}
				l.BannedURIs = d.Val()
			default:
				return d.Errf("theres a bit too many subdirectives here, remove: '%s'", d.Val())
			}
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

	values := map[string]string{"ip": ip, "categories": "18", "comment": "This IP accessed a banned URI/Path. (ListenCaddy)"}
	json_data, err := json.Marshal(values)

	if err != nil {
		fmt.Print(err)
	}

	resp, err := http.Post("https://api.abuseipdb.com/api/v2/report", "application/json",
		bytes.NewBuffer(json_data))

	resp.Header.Set("Key", l.APIKey)
	if err != nil {
		fmt.Print(err)
	}

	var res map[string]interface{}

	json.NewDecoder(resp.Body).Decode(&res)

	fmt.Println(res["json"])

	return nil
}
