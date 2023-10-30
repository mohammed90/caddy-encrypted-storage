Caddy Encrypted Storage
======================

The Caddy Encrypted Storage plugin is a storage plugin for Caddy that encrypts and decrypts files on the fly using [SOPS](https://github.com/getsops/sops).

## Install

Like all other Caddy modules, you can build Caddy with this plugin using `xcaddy`:

```shell
xcaddy build --with github.com/mohammed90/caddy-encrypted-storage
```

## Data Sample

The stored data is a JSON object. A run with the sample data in the module tests produces the following file stored in the backing storage:

```json
{
	"data": "ENC[AES256_GCM,data:BbJmihdruQHuFGYx1B6hb0AL,iv:xpaItMxmt7ZEUzC5q2jugwyDsipfApTzFkm7zzyG3bI=,tag:53XIOqcvYx6hdW91Hynwhg==,type:str]",
	"sops": {
		"kms": null,
		"gcp_kms": null,
		"azure_kv": null,
		"hc_vault": null,
		"age": [
			{
				"recipient": "age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2",
				"enc": "-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBkOEIzME1kNzhuaDVaRWh6\neTduK29lenZvNU9oejBLV2xkL2hOaVJ4Sml3CjY4NkVmT1h0bFE0ZXFiNmlPUTMz\nRXZNVVlhbEs0Um1ZM3BNbkx3WUZPam8KLS0tIEdIU295WGs2MmIvb0VPVCthZkwr\nN25aSi8yU3dsVlBxeHlnRkVLQlNjcWsKNaaOKatV+ncmpEYVuR4g40Njv8RIce+d\nMTV1koLrdXYFA5k0Xtjs/Xg9NocYFfs8aW2XgX8J3mSoy6lVKMwBsQ==\n-----END AGE ENCRYPTED FILE-----\n"
			}
		],
		"lastmodified": "2023-10-30T13:06:37Z",
		"mac": "ENC[AES256_GCM,data:kQLUguFnLQCT50fuHL7L3xeHoMTbC7JKLker1Y2S4prSZbu5QfJ5D44nd/ETpMMak/LFvRnhIEsBkeBNZxpcsTGkyMpAN8GG9C9+Cc2YAgPvm7Ubl+pQuPUp84ExXk7896l7zwWlY1XrITOiZ5PsZOiy1ZbMV+WEG6YQ5QWk4JY=,iv:+VnRSwOWupu1dlfeCG+aZU4yNuH0B2eVvkvHgXJbxTE=,tag:+lU43WSEp489EcV7RPhJ6w==,type:str]",
		"pgp": null,
		"version": ""
	}
}
```

## Example

### Caddyfile

Configuring the default storage module for Caddy in the Caddyfile is done using the `storage` global option.

```caddyfile
{
	storage encrypted {
		backend file_system {
			root /var/caddy/storage
		}
		provider local {
			key age {
				recipient age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2
				identity AGE-SECRET-KEY-16E6P6H93CXNPZQRJVNA5NMK4X06ZHCDU4ED9U89E3PZMASSMC46SX99PEWAGE-SECRET-KEY-16E6P6H93CXNPZQRJVNA5NMK4X06ZHCDU4ED9U89E3PZMASSMC46SX99PEW
				identity {$AGE_SECRET_KEY}
			}
		}
	}
}
https://example.com {
	respond "Howdy!"
}
```

### JSON

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
