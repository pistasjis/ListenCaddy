package listencaddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"text/template"

	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ListenCaddy{})
	httpcaddyfile.RegisterHandlerDirective("listencaddy", parseCaddyfile)
}

// ListenCaddy is a Caddy http.handlers module that listens for requests to specific URIs/paths and reports IPs that hit these URIs to AbuseIPDB.
type ListenCaddy struct {
	// APIKey is the API key from AbuseIPDB.
	APIKey string `json:"apikey,omitempty"`
	// BannedURIs is a regex of banned URIs/paths.
	BannedURIs string `json:"banned_uris,omitempty"`
	// WhitelistedIPs is a regex of whitelisted IPs. (optional)
	WhitelistedIPs string `json:"whitelisted_ips,omitempty"`
	// AbuseIPDBMessage is the message that will be sent to AbuseIPDB. Uses Go templates (do {{.Path}} to get path accessed) (optional)
	AbuseIPDBMessage string `json:"abuseipdb_message,omitempty"`
	// ResponseMessage is the message that will be sent to the client accessing a resource they're not supposed to. Uses Go templates (do {{.Path}} to get path accessed) (optional)
	ResponseMessage string `json:"respond_message,omitempty"`

	Logger *zap.Logger
}

func (ListenCaddy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.listencaddy",
		New: func() caddy.Module { return new(ListenCaddy) },
	}
}

func (l *ListenCaddy) Provision(ctx caddy.Context) error {
	l.Logger = ctx.Logger(l)
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
	// used multiple times and seems to blank out after it's used for a bit
	path := r.URL.Path
	match, _ := regexp.MatchString(l.BannedURIs, path)
	var response_message string

	split := regexp.MustCompile(`((?::))(?:[0-9]+)$`).Split(r.RemoteAddr, -1)
	if match {
		if l.WhitelistedIPs != "" {
			isWhitelisted, _ := regexp.MatchString(l.WhitelistedIPs, split[0])
			if isWhitelisted {
				l.Logger.Info("Whitelisted IP accessed a banned URI/path", zap.String("ip", split[0]), zap.String("path", path), zap.String("whitelisted_ips", l.WhitelistedIPs))
				return next.ServeHTTP(w, r)
			}
		}

		if l.ResponseMessage != "" {
			type Response struct {
				Path string
			}

			response := Response{
				Path: path,
			}

			tmpl, err := template.New("respond_message").Parse(l.ResponseMessage)
			if err != nil {
				l.Logger.Info("Error parsing RespondMessage", zap.String("error", err.Error()))
			}

			var tmpl_output bytes.Buffer
			templateExecuteError := tmpl.Execute(&tmpl_output, response)
			if templateExecuteError != nil {
				l.Logger.Info("Error executing RespondMessage", zap.String("error", templateExecuteError.Error()))
			}

			response_message = tmpl_output.String()
		} else {
			response_message = path + " is a banned path. Powered by ListenCaddy"
		}

		go func(l ListenCaddy) {
			l.Logger.Info("Reporting IP to AbuseIPDB", zap.String("ip", split[0]), zap.String("path", path))

			// HTTP endpoint
			posturl := "https://api.abuseipdb.com/api/v2/report"

			var abuseipdb_comment string

			// check if AbuseIPDBMessage is set
			if l.AbuseIPDBMessage != "" {

				type Comment struct {
					Path string
				}

				comment := Comment{
					Path: path,
				}

				tmpl, err := template.New("abuseipdb_comment").Parse(l.AbuseIPDBMessage)
				if err != nil {
					l.Logger.Info("Error parsing AbuseIPDBMessage", zap.String("error", err.Error()))
				}

				var tmpl_output bytes.Buffer
				templateExecuteError := tmpl.Execute(&tmpl_output, comment)
				if templateExecuteError != nil {
					l.Logger.Info("Error executing AbuseIPDBMessage", zap.String("error", templateExecuteError.Error()))
				}

				abuseipdb_comment = tmpl_output.String()
			} else {
				abuseipdb_comment = "This IP accessed a banned path: " + path + ". (ListenCaddy)"
			}

			reportJSON := AbuseIPDBReport{
				IP:         split[0],
				Categories: "19,21",
				Comment:    abuseipdb_comment,
			}

			body, _ := json.Marshal(reportJSON)
			// Create a HTTP post request
			r, err := http.NewRequest("POST", posturl, bytes.NewBuffer(body))
			if err != nil {
				panic(err)
			}
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json")
			r.Header.Add("Key", l.APIKey)

			client := &http.Client{}
			res, err := client.Do(r)
			if err != nil {
				panic(err)
			}

			defer res.Body.Close()
		}(l)
		// close connection using caddyhttp.StaticResponse
		return caddyhttp.StaticResponse{
			StatusCode: "403",
			Body:       response_message,
			Close:      true,
		}.ServeHTTP(w, r, next)
	} else {
		return next.ServeHTTP(w, r)
	}
}

type AbuseIPDBReport struct {
	IP         string `json:"ip"`
	Categories string `json:"categories"`
	Comment    string `json:"comment"`
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
			case "whitelisted_ips":
				if !d.NextArg() {
					return d.ArgErr()
				}
				l.WhitelistedIPs = d.Val()
			case "abuseipdb_message":
				if !d.NextArg() {
					return d.ArgErr()
				}
				l.AbuseIPDBMessage = d.Val()
			case "response_message":
				if !d.NextArg() {
					return d.ArgErr()
				}
				l.ResponseMessage = d.Val()
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
