package encryptedstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Remote{})
}

type Remote struct {
	Address string `json:"address,omitempty"`

	Keys       []json.RawMessage `json:"keys,omitempty" caddy:"namespace=caddy.storage.encrypted.key inline_key=type"`
	keysGroups []sops.KeyGroup

	ctx  context.Context
	conn *grpc.ClientConn
}

// KeyServiceClient implements KeyServiceClientProvider.
func (r *Remote) KeyServiceClient() keyservice.KeyServiceClient {
	return keyservice.NewKeyServiceClient(r.conn)
}

// KeyGroup implements KeyGroupGetter.
func (s *Remote) KeyGroup() []sops.KeyGroup {
	return s.keysGroups
}

// CaddyModule implements caddy.Module.
func (Remote) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.encrypted.remote",
		New: func() caddy.Module {
			return new(Remote)
		},
	}
}

// Provision implements caddy.Provisioner.
func (s *Remote) Provision(ctx caddy.Context) error {
	s.ctx = ctx
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

// Cleanup implements caddy.CleanerUpper.
func (r *Remote) Cleanup() error {
	return r.conn.Close()
}

// Validate implements caddy.Validator.
func (r *Remote) Validate() error {
	c, err := grpc.DialContext(r.ctx, r.Address)
	if err != nil {
		return fmt.Errorf("failed to connect to key service: %v", err)
	}
	r.conn = c
	return nil
}

var (
	_ caddy.Module       = (*Remote)(nil)
	_ caddy.Provisioner  = (*Remote)(nil)
	_ caddy.Validator    = (*Remote)(nil)
	_ caddy.CleanerUpper = (*Remote)(nil)
	// _ keyservice.KeyServiceServer = (*Remote)(nil)
	_ KeyGroupProvider         = (*Remote)(nil)
	_ KeyServiceClientProvider = (*Remote)(nil)
)
