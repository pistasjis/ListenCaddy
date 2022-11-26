# ListenCaddy
A Caddy 2 module that **listens** for **abuse** and reports abuse to AbuseIPDB.

[![Go Report Card](https://goreportcard.com/badge/github.com/DrivetDevelopment/ListenCaddy)](https://goreportcard.com/report/github.com/DrivetDevelopment/ListenCaddy) [![Build Artifact](https://github.com/Odyssey346/ListenCaddy/actions/workflows/build-artifact.yml/badge.svg)](https://github.com/Odyssey346/ListenCaddy/actions/workflows/build-artifact.yml)

## Setup
You will need the following before you can begin using ListenCaddy:
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
    order listencaddy before file_server
}
```
This tells Caddy to prioritize ListenCaddy before anything else, which is required.

Now, you can set up a website to use ListenCaddy. Here's an example (oh also, we use RegEx):
```caddyfile
listencaddy {
        api_key "yourAPIkey"
        banned_uris "/admin|/wp-admin|/.env|/phpMyAdmin/scripts/setup.php" # TODO: add more of these. If you want to help, contribute here: https://github.com/DrivetDevelopment/Wiki/blob/main/listencaddy/get-started.md
}
```

If you don't like repetition, then you can do something like this:

```caddyfile
(listencaddy) {
	listencaddy {
		api_key "yourAPIkey"
		banned_uris "/admin|/wp-admin|/.env|/phpMyAdmin/scripts/setup.php"
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