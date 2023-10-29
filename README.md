Caddy Encrypted Storage
======================

The Caddy Encrypted Storage plugin is a storage plugin for Caddy that encrypts and decrypts files on the fly using [SOPS](https://github.com/getsops/sops).

## Install

Like all other Caddy modules, you can build Caddy with this plugin using `xcaddy`:

```shell
xcaddy build --with github.com/mohammed90/caddy-encrypted-storage
```

## Example

The simplest configuration of this module can be as follows:

```json
{
	"storage": {
		"module": "encrypted",
		"backend": {
			"module": "file_system",
			"root": "/var/caddy/storage"
		},
		"encryption":[
			{
				"provider": "local",
				"keys": [
					{
						"type": "age",
						"recipient": "age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2",
						"identities": ["AGE-SECRET-KEY-16E6P6H93CXNPZQRJVNA5NMK4X06ZHCDU4ED9U89E3PZMASSMC46SX99PEW"]
					}
				]
			}
		]
	}
	// ... rest of Caddy configuration
}
```

The module supports replaceable values ([placeholders](https://caddyserver.com/docs/conventions#placeholders)) where the actual values can be obtained from Caddy runtime or the environment. For instance, the earlier configuration can be changed to:

```json
{
	"storage": {
		"module": "encrypted",
		"backend": {
			"module": "file_system",
			"root": "/var/caddy/storage"
		},
		"encryption":[
			{
				"provider": "local",
				"keys": [
					{
						"type": "age",
						"recipient": "age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2",
						"identities": ["{env.AGE_IDENTITY_0}"]
					}
				]
			}
		]
	}
	// ... rest of Caddy configuration
}
```