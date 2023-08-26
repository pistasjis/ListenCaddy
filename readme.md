# ListenCaddy
A Caddy 2 module that **listens** for **abuse** and reports abuse to AbuseIPDB.

[![Go Report Card](https://goreportcard.com/badge/github.com/Odyssey346/ListenCaddy)](https://goreportcard.com/report/github.com/Odyssey346/ListenCaddy) [![Build Artifact](https://github.com/Odyssey346/ListenCaddy/actions/workflows/build-artifact.yml/badge.svg)](https://github.com/Odyssey346/ListenCaddy/actions/workflows/build-artifact.yml)

## Setup

### From Caddy
Caddy now supports adding packages via ``caddy add-package``. This is the easiest way to install ListenCaddy.

Just run ``caddy add-package github.com/Odyssey346/ListenCaddy`` and you're done! You can now use ListenCaddy in your Caddyfile.

This gets built from Caddy's servers, so you don't need to build it yourself and you don't need any extra dependencies other than Caddy itself. It's also way faster than building it yourself.

### BYOC (Build Your Own Caddy)

**Note: these instructions are made for Linux. It shouldn't be too different on other UNIX\* systems, but I haven't tried (and can't). If you have instructions for Windows, please make a PR.**

You will need the following before you can build Caddy with ListenCaddy:
- A server
- [xcaddy](https://github.com/caddyserver/xcaddy)
- An [AbuseIPDB](https://www.abuseipdb.com/) account and API key ready
- A working installation of Go that is a version higher than 1.16 (preferably the latest Go version)

When you have xcaddy set up, run this command to build a custom version of Caddy that includes ListenCaddy:
```bash
xcaddy build --with github.com/Odyssey346/ListenCaddy
```

You should get a binary called ``caddy`` in your current directory. This is the custom Caddy server.

If you have a version of Caddy installed, I recommend you remove it. If you're on Linux, it's as simple as ``sudo rm /usr/bin/caddy``.

Now we move the binary to ``/usr/bin/caddy`` and make it executable:
```bash
sudo mv caddy /usr/bin/caddy
sudo chmod +x /usr/bin/caddy
```

### Setting up the new Caddyfile
Open up your Caddyfile using your favourite editor and add the following to the top:
```caddyfile
{
    order listencaddy first
}
```
This tells Caddy to prioritize ListenCaddy before anything else, which is required.

Now, you can set up a website to use ListenCaddy. Here's an example (oh also, we use RegEx):
```caddyfile
listencaddy {
        api_key "yourAPIkey" # You can use an environment variable if you'd like. If you want to, do "{$YOUR_ENV_VAR_NAME}".
        banned_uris "/admin|/wp-admin|/.env|/phpMyAdmin/scripts/setup.php" # TODO: add more of these. If you want to help, contribute!
		whitelisted_ips "1.1.1.1|9.9.9.9" #optional
		abuseipdb_message "This IP accessed the path {{.Path}}, which is banned. Powered by ListenCaddy" # Optional. This is the message that gets sent to AbuseIPDB as comment. Take a look at Template Options below for some information you can put in your report.
		response_message "{{.Path}} is banned. Powered by ListenCaddy" # Optional. This is the message that gets sent to the client when they accessed a banned path.
		Take a look at Template Options below for some information you can put in your response.
}
```

If you don't like repetition, then you can do something like this:

```caddyfile
(listencaddy) {
	listencaddy {
			api_key "yourAPIkey" # You can use an environment variable if you'd like. If you want to, do "{$YOUR_ENV_VAR_NAME}".
			banned_uris "/admin|/wp-admin|/.env|/phpMyAdmin/scripts/setup.php" # TODO: add more of these. If you want to help, contribute!
			whitelisted_ips "1.1.1.1|9.9.9.9" #optional
			abuseipdb_message "This IP accessed the path {{.Path}}, which is banned. Powered by ListenCaddy" # Optional. This is the message that gets sent to AbuseIPDB as comment. This is the message that gets sent to the client when they accessed a banned path. Take a look at Template Options below for some information you can put in your report.
			response_message "{{.Path}} is banned. Powered by ListenCaddy" # Optional. This is the message that gets sent to the client when they accessed a banned path. Take a look at Template Options below for some information you can put in your response.
	}
}

yourdomain.xyz {
	import listencaddy
	reverse_proxy http://127.0.0.1:3000
}

yourotherdomain.xyz {
	import listencaddy
	respond / "Hello world!" 200
}
```

### Template Options

ListenCaddy allows you to get some information about the reported user in the AbuseIPDB report or as a response.

| Variable | What it does |
| -------- | ------------ |
| .Path    | Tells you what path the abusive IP accessed. For example, /admin. |
| .UserAgent | Tells you what User-Agent the abusive IP used. For example, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36". |