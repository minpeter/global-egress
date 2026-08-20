package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
)

// TestExampleConfigsParseStrictly pins the shipped examples to the strict
// schema: if a field is renamed or removed in code, or drift sneaks into an
// example, this fails before a user copies the file.
func TestExampleConfigsParseStrictly(t *testing.T) {
	examples := []string{
		filepath.Join("..", "..", "deploy", "config.example.toml"),
		filepath.Join("..", "..", "deploy", "docker", "config.example.toml"),
	}
	for _, path := range examples {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read example: %v", err)
			}
			var input rawConfig
			metadata, err := toml.Decode(string(raw), &input)
			if err != nil {
				t.Fatalf("example does not parse: %v", err)
			}
			if undecoded := metadata.Undecoded(); len(undecoded) != 0 {
				t.Fatalf("example contains unknown field %q", undecoded[0])
			}
			if _, err := normalizeProviders(input.Providers); err != nil {
				t.Fatalf("example providers invalid: %v", err)
			}
		})
	}
}
