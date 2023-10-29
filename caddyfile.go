package encryptedstorage

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func (s *Storage) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "backend":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if s.RawBackend != nil {
				return d.Err("backend module already specified")
			}
			name := d.Val()
			modID := "caddy.storage." + name
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return err
			}
			backend, ok := unm.(caddy.StorageConverter)
			if !ok {
				return d.Errf("module %s (%T) is not a supported storage implementation (requires caddy.StorageConvertor)", modID, unm)
			}
			s.RawBackend = caddyconfig.JSONModuleObject(backend, "module", name, nil)
		case "provider":
			if !d.NextArg() {
				return d.ArgErr()
			}
			name := d.Val()
			modID := "caddy.storage.encrypted.provider." + name
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return err
			}
			s.Encryption = append(s.Encryption, caddyconfig.JSONModuleObject(unm, "provider", name, nil))
		default:
			return d.Errf("unrecognized parameter '%s'", d.Val())
		}
	}
	return nil
}

func (s *Local) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			name := d.Val()
			modID := "caddy.storage.encrypted.key." + name
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return err
			}
			k, ok := unm.(MasterkeyConverter)
			if !ok {
				return d.Errf("module %s (%T) is not a supported storage implementation (requires caddy.StorageConvertor)", modID, unm)
			}
			s.Keys = append(s.Keys, caddyconfig.JSONModuleObject(k, "type", name, nil))
		default:
			return d.Errf("unrecognized parameter '%s'", d.Val())
		}
	}
	return nil
}

func (s *Age) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "recipient":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if len(s.Recipient) > 0 {
				return d.Err("recipient already specified")
			}
			s.Recipient = d.Val()
		case "identity":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.Identities = append(s.Identities, d.Val())
		default:
			return d.Errf("unrecognized parameter '%s'", d.Val())
		}
	}
	return nil
}

func (s *GCPKMS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "resource_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if len(s.ResourceID) > 0 {
				return d.Err("resource_id already specified")
			}
			s.ResourceID = d.Val()
		case "credentials":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.Credentials = json.RawMessage(d.Val())
		default:
			return d.Errf("unrecognized parameter '%s'", d.Val())
		}
	}
	return nil
}
