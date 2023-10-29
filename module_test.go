package encryptedstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/caddyserver/certmagic"
	"github.com/getsops/sops/v3/age"
)

func must(k *age.MasterKey, e error) *age.MasterKey {
	if e != nil {
		panic(e)
	}
	return k
}

const (
	key       = "complex-data-key"
	val       = "complex-data-value"
	recipient = "age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2"
	ageId     = "AGE-SECRET-KEY-16E6P6H93CXNPZQRJVNA5NMK4X06ZHCDU4ED9U89E3PZMASSMC46SX99PEW"
	dataDir   = "test-ground"
)

func TestStorageWithAgeEncryption(t *testing.T) {
	if err := os.Mkdir(dataDir, 0755); err != nil {
		t.Errorf("error creating data dir: %s", err)
		t.FailNow()
		return
	}
	t.Cleanup(func() {
		os.RemoveAll(dataDir)
	})
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	s := Storage{
		RawBackend: json.RawMessage(fmt.Sprintf(`{"module": "file_system", "root": "%s"}`, dataDir)),
		Encryption: []json.RawMessage{json.RawMessage(fmt.Sprintf(`{"provider":"local", "keys": [{"type":"age", "recipient": "%s", "identities": ["%s"]}]}`, recipient, ageId))},
	}
	if err := s.Provision(ctx); err != nil {
		t.Errorf("error provisioning: %s", err)
		return
	}
	err := s.Store(ctx, key, []byte(val))
	if err != nil {
		t.Error(err)
	}
	if !s.Exists(ctx, key) {
		t.Errorf("key '%s' should exist", key)
		return
	}

	fdata, err := os.ReadFile(fmt.Sprintf("%s/%s", dataDir, key))
	if err != nil {
		t.Errorf("error reading file: %s", err)
		return
	}
	if bytes.Contains(fdata, []byte(val)) {
		t.Errorf("file data should contain '%s'", val)
		return
	}

	stat, err := s.Stat(ctx, key)
	if err != nil {
		t.Errorf("stat: %v", err)
		return
	}
	if stat == (certmagic.KeyInfo{}) {
		t.Errorf("stat: size mismatch: %d!= %d", stat.Size, len(val))
		return
	}
	data, err := s.Load(ctx, key)
	if err != nil {
		t.Errorf("load: %v", err)
		return
	}
	if string(data) != val {
		t.Errorf("load: data mismatch: %s!= %s", data, val)
		return
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Errorf("delete: %v", err)
		return
	}
	if s.Exists(ctx, key) {
		t.Errorf("key '%s' should not exist", key)
		return
	}
}

func TestCaddyfileAdaptToJSON(t *testing.T) {
	testcases := []struct {
		name   string
		input  string
		output string
		fails  bool
	}{
		{
			name: "happy scenario",
			input: fmt.Sprintf(`{
	storage encrypted {
		backend file_system {
			root /var/caddy/storage
		}
		provider local {
			key age {
				recipient %s
				identity %s
			}
		}
	}
}
`, recipient, ageId),
			output: `{
	"storage": {
		"backend": {
			"module": "file_system",
			"root": "/var/caddy/storage"
		},
		"encryption": [
			{
				"keys": [
					{
						"identities": [
							"AGE-SECRET-KEY-16E6P6H93CXNPZQRJVNA5NMK4X06ZHCDU4ED9U89E3PZMASSMC46SX99PEW"
						],
						"recipient": "age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2",
						"type": "age"
					}
				],
				"provider": "local"
			}
		],
		"module": "encrypted"
	}
}`,
		},
	}
	for i, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ok := caddytest.CompareAdapt(t, tc.name, tc.input, "caddyfile", tc.output)
			if !ok {
				t.Errorf("failed to adapt test case number '%d', named '%s'", i, tc.name)
			}
		})

	}
}
