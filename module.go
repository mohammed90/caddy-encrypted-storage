package encryptedstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
	jsonstore "github.com/getsops/sops/v3/stores/json"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Storage{})
}

// MasterkeyConverter allows conversion from the custom key type
// to SOPS `keys.MasterKey` interface type
type MasterkeyConverter interface {
	ToMasterkey() keys.MasterKey
}

// KeyGroupProvider allows the `encrypted` storage module to
// obtain the keys from the encryption provider
type KeyGroupProvider interface {
	KeyGroup() []sops.KeyGroup
}

// KeyServiceClientProvider allows the `encrypted` storage module
// to obtain the encryption/decryption client conforming to the
// provider.
type KeyServiceClientProvider interface {
	KeyServiceClient() keyservice.KeyServiceClient
}

// Storage is the impelementation of certmagic.Storage interface for Caddy with encryption/decryption layer
// using [SOPS](https://github.com/getsops/sops). The module accepts any Caddy storage module as the backend.
type Storage struct {
	// The backing storage where the encrypted data is stored.
	RawBackend json.RawMessage `json:"backend,omitempty" caddy:"namespace=caddy.storage inline_key=module"`
	backend    certmagic.Storage

	// The encryption provider: local, remote. Although this is an array, current support is for 1 provider.
	// TODO: implemented the `remote` provider.
	// TODO: multiple providers
	Encryption        []json.RawMessage `json:"encryption,omitempty" caddy:"namespace=caddy.storage.encrypted.provider inline_key=provider"`
	keyServiceClients []keyservice.KeyServiceClient
	keyGroups         []sops.KeyGroup

	store  sops.Store
	logger *zap.Logger
}

// CaddyModule implements caddy.Module.
func (Storage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.storage.encrypted",
		New: func() caddy.Module { return new(Storage) },
	}
}

// CertMagicStorage implements caddy.StorageConverter.
func (s *Storage) CertMagicStorage() (certmagic.Storage, error) {
	return s, nil
}

// Provision implements caddy.Provisioner.
func (s *Storage) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger(s)
	istore, err := ctx.LoadModule(s, "RawBackend")
	if err != nil {
		return err
	}
	s.backend, _ = istore.(caddy.StorageConverter).CertMagicStorage()

	if len(s.Encryption) == 0 {
		return fmt.Errorf("field 'encryption' cannot be empty")
	}
	if len(s.Encryption) > 1 {
		return fmt.Errorf("only 1 provider is supported")
	}
	iencrypt, err := ctx.LoadModule(s, "Encryption")
	if err != nil {
		return err
	}
	for _, iface := range iencrypt.([]any) {
		if clp, ok := iface.(KeyServiceClientProvider); ok {
			s.keyServiceClients = append(s.keyServiceClients, clp.KeyServiceClient())
		}
		if kgp, ok := iface.(KeyGroupProvider); ok {
			s.keyGroups = append(s.keyGroups, kgp.KeyGroup()...)
		}
	}

	s.store = &jsonstore.BinaryStore{}

	return nil
}

// Delete implements certmagic.Storage.
func (s *Storage) Delete(ctx context.Context, key string) error {
	return s.backend.Delete(ctx, key)
}

// Exists implements certmagic.Storage.
func (s *Storage) Exists(ctx context.Context, key string) bool {
	return s.backend.Exists(ctx, key)
}

// List implements certmagic.Storage.
func (s *Storage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	return s.backend.List(ctx, path, recursive)
}

// Load implements certmagic.Storage.
func (s *Storage) Load(ctx context.Context, key string) ([]byte, error) {
	bs, err := s.backend.Load(ctx, key)
	if err != nil {
		return bs, fmt.Errorf("backend load error: %s", err)
	}

	tree, err := s.store.LoadEncryptedFile(bs)
	if err != nil {
		return nil, fmt.Errorf("error loading encrypted file: %s", err)
	}
	tree.FilePath = key

	_, err = common.DecryptTree(common.DecryptTreeOpts{
		Tree:        &tree,
		KeyServices: s.keyServiceClients,
		IgnoreMac:   false,
		Cipher:      aes.NewCipher(),
	})
	if err != nil {
		return nil, fmt.Errorf("error decrypting tree: %s", err)
	}

	return s.store.EmitPlainFile(tree.Branches)
}

// Stat implements certmagic.Storage.
func (s *Storage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	return s.backend.Stat(ctx, key)
}

// Store implements certmagic.Storage.
func (s *Storage) Store(ctx context.Context, key string, value []byte) error {
	branches, err := s.store.LoadPlainFile(value)
	if err != nil {
		return nil
	}

	if len(branches) < 1 {
		return errors.New("file cannot be completely empty, it must contain at least one document")
	}

	cipher := aes.NewCipher()

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			LastModified: time.Now().UTC(),
			KeyGroups:    s.keyGroups,
		},
		FilePath: key,
	}

	dataKey, errs := tree.GenerateDataKeyWithKeyServices(s.keyServiceClients)
	if len(errs) > 0 {
		return fmt.Errorf("could not generate data key: %s", errs)
	}
	if err := common.EncryptTree(common.EncryptTreeOpts{
		Tree:    &tree,
		Cipher:  cipher,
		DataKey: dataKey,
	}); err != nil {
		return err
	}

	encryptedFile, err := s.store.EmitEncryptedFile(tree)
	if err != nil {
		return err
	}

	return s.backend.Store(ctx, key, encryptedFile)
}

// Lock implements certmagic.Storage.
func (s *Storage) Lock(ctx context.Context, name string) error {
	return s.backend.Lock(ctx, name)
}

// Unlock implements certmagic.Storage.
func (s *Storage) Unlock(ctx context.Context, name string) error {
	return s.backend.Unlock(ctx, name)
}

var (
	_ caddy.Module           = (*Storage)(nil)
	_ caddy.Provisioner      = (*Storage)(nil)
	_ certmagic.Storage      = (*Storage)(nil)
	_ caddy.StorageConverter = (*Storage)(nil)
)
