package encryptedstorage

import (
	"encoding/json"
	"errors"

	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/keys"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(GCPKMS{})
}

// GCPKMS uses GCPKMS (Google Cloud Platform KMS) for the encryption/decryption.
// See more: [https://github.com/getsops/sops#encrypting-using-gcp-kms](https://github.com/getsops/sops#encrypting-using-gcp-kms)
type GCPKMS struct {
	ResourceID  string          `json:"resource_id,omitempty"`
	Credentials json.RawMessage `json:"credentials,omitempty"`

	mk keys.MasterKey
}

// Provision implements caddy.Provisioner.
func (gcp *GCPKMS) Provision(ctx caddy.Context) error {
	if len(gcp.ResourceID) == 0 {
		return errors.New("missing resource_id")
	}
	r, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		r = caddy.NewReplacer()
	}
	mk := gcpkms.NewMasterKeyFromResourceID(r.ReplaceKnown(gcp.ResourceID, ""))
	if len(gcp.Credentials) > 0 {
		gcpkms.CredentialJSON(gcp.Credentials).ApplyToMasterKey(mk)
	}
	gcp.mk = mk
	return nil
}

// CaddyModule implements caddy.Module.
func (GCPKMS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.encrypted.key.gcp_kms",
		New: func() caddy.Module {
			return new(GCPKMS)
		},
	}
}

// ToMasterkey implements Masterkeyer.
func (gcp *GCPKMS) ToMasterkey() keys.MasterKey {
	return gcp.mk
}

var (
	_ caddy.Module       = (*GCPKMS)(nil)
	_ caddy.Provisioner  = (*GCPKMS)(nil)
	_ MasterkeyConverter = (*GCPKMS)(nil)
)
