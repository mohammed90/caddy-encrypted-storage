// Much of the content of this file is copied from getsops/sops project at the following source with minor modifications:
// https://github.com/getsops/sops/blob/d7c2d7d30f1e3991c8646c1ad829a1c34263e05c/keyservice/server.go
// Per the terms of the MPL-2.0, the following applies:
// - The file (and the projct) retains the same license.
// - The file (and the project) retains the copyright notice. The source does not contain copyright notice,
// but the copyright of this code is assigned to original authors.
package encryptedstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/hcvault"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Local{})
}

// Local encryption provider avails in-process encryption/decryption capabilities
type Local struct {
	// The encryption/decryption keyset
	Keys       []json.RawMessage `json:"keys,omitempty" caddy:"namespace=caddy.storage.encrypted.key inline_key=type"`
	keysGroups []sops.KeyGroup

	s keyservice.Server
}

// KeyServiceClient implements KeyServiceClientProvider.
func (l *Local) KeyServiceClient() keyservice.KeyServiceClient {
	return keyservice.NewCustomLocalClient(l)
}

// CaddyModule implements caddy.Module.
func (Local) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.encrypted.provider.local",
		New: func() caddy.Module {
			return new(Local)
		},
	}
}

// KeyGroup implements KeyGroupGetter.
func (s *Local) KeyGroup() []sops.KeyGroup {
	return s.keysGroups
}

// Provision implements caddy.Provisioner.
func (s *Local) Provision(ctx caddy.Context) error {
	if len(s.Keys) == 0 {
		return errors.New("field 'keys' cannot be empty")
	}
	iKeys, err := ctx.LoadModule(s, "Keys")
	if err != nil {
		return err
	}
	for _, iKey := range iKeys.([]any) {
		key, ok := iKey.(MasterkeyConverter)
		if !ok {
			return fmt.Errorf("expected key to be of type sops.Key, but got %T", iKey)
		}
		s.keysGroups = append(s.keysGroups, sops.KeyGroup{key.ToMasterkey()})
	}

	return nil
}

// Encrypt implements keyservice.KeyServiceServer.
func (s *Local) Encrypt(ctx context.Context, req *keyservice.EncryptRequest) (*keyservice.EncryptResponse, error) {
	return s.s.Encrypt(ctx, req)
}

// Decrypt takes a decrypt request and decrypts the provided ciphertext with the provided key, returning the decrypted
// result
func (ks Local) Decrypt(ctx context.Context, req *keyservice.DecryptRequest) (*keyservice.DecryptResponse, error) {
	key := req.Key
	var response *keyservice.DecryptResponse
	switch k := key.KeyType.(type) {
	case *keyservice.Key_PgpKey:
		plaintext, err := ks.decryptWithPgp(k.PgpKey, req.Ciphertext)
		if err != nil {
			return nil, err
		}
		response = &keyservice.DecryptResponse{
			Plaintext: plaintext,
		}
	case *keyservice.Key_KmsKey:
		plaintext, err := ks.decryptWithKms(k.KmsKey, req.Ciphertext)
		if err != nil {
			return nil, err
		}
		response = &keyservice.DecryptResponse{
			Plaintext: plaintext,
		}
	case *keyservice.Key_GcpKmsKey:
		plaintext, err := ks.decryptWithGcpKms(k.GcpKmsKey, req.Ciphertext)
		if err != nil {
			return nil, err
		}
		response = &keyservice.DecryptResponse{
			Plaintext: plaintext,
		}
	case *keyservice.Key_AzureKeyvaultKey:
		plaintext, err := ks.decryptWithAzureKeyVault(k.AzureKeyvaultKey, req.Ciphertext)
		if err != nil {
			return nil, err
		}
		response = &keyservice.DecryptResponse{
			Plaintext: plaintext,
		}
	case *keyservice.Key_VaultKey:
		plaintext, err := ks.decryptWithVault(k.VaultKey, req.Ciphertext)
		if err != nil {
			return nil, err
		}
		response = &keyservice.DecryptResponse{
			Plaintext: plaintext,
		}
	case *keyservice.Key_AgeKey:
		plaintext, err := ks.decryptWithAge(k.AgeKey, req.Ciphertext)
		if err != nil {
			return nil, err
		}
		response = &keyservice.DecryptResponse{
			Plaintext: plaintext,
		}
	case nil:
		return nil, status.Errorf(codes.NotFound, "Must provide a key")
	default:
		return nil, status.Errorf(codes.NotFound, "Unknown key type")
	}
	return response, nil
}

func (ks *Local) decryptWithPgp(key *keyservice.PgpKey, ciphertext []byte) ([]byte, error) {
	pgpKey := pgp.NewMasterKeyFromFingerprint(key.Fingerprint)
	pgpKey.EncryptedKey = string(ciphertext)
	plaintext, err := pgpKey.Decrypt()
	return plaintext, err
}

func (ks *Local) decryptWithKms(key *keyservice.KmsKey, ciphertext []byte) ([]byte, error) {
	kmsKey := kmsKeyToMasterKey(key)
	kmsKey.EncryptedKey = string(ciphertext)
	plaintext, err := kmsKey.Decrypt()
	return plaintext, err
}

func (ks *Local) decryptWithGcpKms(key *keyservice.GcpKmsKey, ciphertext []byte) ([]byte, error) {
	for _, kg := range ks.keysGroups {
		for _, mk := range kg {
			amk, ok := mk.(*gcpkms.MasterKey)
			if !ok {
				continue
			}
			gcpKey := *amk
			gcpKey.EncryptedKey = string(ciphertext)
			if res, err := gcpKey.Decrypt(); err == nil {
				return res, nil
			}
		}
	}
	return nil, errors.New("cannot be decrypted")
}

func (ks *Local) decryptWithAzureKeyVault(key *keyservice.AzureKeyVaultKey, ciphertext []byte) ([]byte, error) {
	azkvKey := azkv.MasterKey{
		VaultURL: key.VaultUrl,
		Name:     key.Name,
		Version:  key.Version,
	}
	azkvKey.EncryptedKey = string(ciphertext)
	plaintext, err := azkvKey.Decrypt()
	return plaintext, err
}

func (ks *Local) decryptWithVault(key *keyservice.VaultKey, ciphertext []byte) ([]byte, error) {
	vaultKey := hcvault.MasterKey{
		VaultAddress: key.VaultAddress,
		EnginePath:   key.EnginePath,
		KeyName:      key.KeyName,
	}
	vaultKey.EncryptedKey = string(ciphertext)
	plaintext, err := vaultKey.Decrypt()
	return plaintext, err
}

func (ks *Local) decryptWithAge(key *keyservice.AgeKey, ciphertext []byte) ([]byte, error) {
	for _, kg := range ks.keysGroups {
		for _, mk := range kg {
			amk, ok := mk.(*age.MasterKey)
			if !ok {
				continue
			}
			ageKey := *amk
			ageKey.EncryptedKey = string(ciphertext)
			if res, err := ageKey.Decrypt(); err == nil {
				return res, nil
			}
		}
	}
	return nil, errors.New("cannot be decrypted")
}

func kmsKeyToMasterKey(key *keyservice.KmsKey) kms.MasterKey {
	ctx := make(map[string]*string)
	for k, v := range key.Context {
		value := v // Allocate a new string to prevent the pointer below from referring to only the last iteration value
		ctx[k] = &value
	}
	return kms.MasterKey{
		Arn:               key.Arn,
		Role:              key.Role,
		EncryptionContext: ctx,
		AwsProfile:        key.AwsProfile,
	}
}

var (
	_ caddy.Module                = (*Local)(nil)
	_ caddy.Provisioner           = (*Local)(nil)
	_ keyservice.KeyServiceServer = (*Local)(nil)
	_ KeyGroupProvider            = (*Local)(nil)
	_ KeyServiceClientProvider    = (*Local)(nil)
)
