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
		return fmt.Errorf("missing API Key from AbuseIPDB. check your Caddyfile and read the docs")
	default:
		return nil
	}
}

func (l *ListenCaddy) Validate() error {
	if l.APIKey == "" {
		return fmt.Errorf("missing API Key from AbuseIPDB. check your Caddyfile and read the docs")
	}
	if l.BannedURIs == "" {
		return fmt.Errorf("can't find any banned URIs/paths. check your Caddyfile and read the docs")
	}
	return nil
}

type Response struct {
	// Path
	Path string
	// User-Agent
	UserAgent string
}

func (l ListenCaddy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// There's a weird but with r.URL.Path where it seems to just be empty after using it for a bit, so I just set a variable to it and that seems to work. Very weird.
	response := Response{
		Path:      r.URL.Path,
		UserAgent: r.UserAgent(),
	}
	match, _ := regexp.MatchString(l.BannedURIs, response.Path)
	var response_message string

	split := regexp.MustCompile(`((?::))(?:[0-9]+)$`).Split(r.RemoteAddr, -1)
	if match {
		if l.WhitelistedIPs != "" {
			isWhitelisted, _ := regexp.MatchString(l.WhitelistedIPs, split[0])
			if isWhitelisted {
				l.Logger.Info("whitelisted IP accessed a banned URI/path", zap.String("ip", split[0]), zap.String("path", response.Path), zap.String("whitelisted_ips", l.WhitelistedIPs))
				return next.ServeHTTP(w, r)
			}
		}

		// If the user has set a custom response message, use that. Otherwise, use the default one.
		if l.ResponseMessage != "" {
			tmpl, err := template.New("respond_message").Parse(l.ResponseMessage)
			if err != nil {
				l.Logger.Info("error parsing RespondMessage", zap.String("error", err.Error()))
			}

			var tmpl_output bytes.Buffer
			templateExecuteError := tmpl.Execute(&tmpl_output, response)
			if templateExecuteError != nil {
				l.Logger.Info("error executing RespondMessage", zap.String("error", templateExecuteError.Error()))
			}

			response_message = tmpl_output.String()
		} else {
			response_message = response.Path + " is a banned path. Powered by ListenCaddy"
		}

		// Report IP to AbuseIPDB in a goroutine
		go func(l ListenCaddy) {
			l.Logger.Info("reporting IP to AbuseIPDB", zap.String("ip", split[0]), zap.String("path", response.Path))

			// HTTP endpoint
			posturl := "https://api.abuseipdb.com/api/v2/report"

			var abuseipdb_comment string

			// check if AbuseIPDBMessage is set. Is it? Use it. Otherwise, use the default message.
			if l.AbuseIPDBMessage != "" {
				tmpl, err := template.New("abuseipdb_comment").Parse(l.AbuseIPDBMessage)
				if err != nil {
					l.Logger.Info("error parsing AbuseIPDBMessage", zap.String("error", err.Error()))
				}

				// I don't like this
				var tmpl_output bytes.Buffer
				templateExecuteError := tmpl.Execute(&tmpl_output, response)
				if templateExecuteError != nil {
					l.Logger.Info("error executing AbuseIPDBMessage", zap.String("error", templateExecuteError.Error()))
				}

				abuseipdb_comment = tmpl_output.String()
			} else {
				abuseipdb_comment = "This IP accessed a banned path: " + response.Path + ". (ListenCaddy)"
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
				l.Logger.Error("error creating HTTP request", zap.String("error", err.Error()))
			}
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json")
			r.Header.Add("Key", l.APIKey)

			client := &http.Client{}
			res, err := client.Do(r)
			if err != nil {
				l.Logger.Error("error sending HTTP request", zap.String("error", err.Error()))
			}

			defer res.Body.Close()
		}(l)
		// send response using Caddy's StaticResponse, which also allows us to close the connection. You should have seen the previous method it used, it was a mess. Hijacking the connection and writing to it directly 🤡
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
	// The IP to report
	IP string `json:"ip"`
	// Categories for the report
	Categories string `json:"categories"`
	// Comment for the report
	Comment string `json:"comment"`
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
