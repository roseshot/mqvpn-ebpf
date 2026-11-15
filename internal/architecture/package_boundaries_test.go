package architecture

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestRuntimePackagesRespectOwnership rejects cross-platform or cross-role
// dependencies that would silently merge Client and Linux Server again.
// Every package is an implementation owner, not a compatibility facade.
func TestRuntimePackagesRespectOwnership(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "internal", "app")); !os.IsNotExist(err) {
		t.Fatalf("obsolete internal/app must not exist: %v", err)
	}
	for _, name := range []string{"client", "server", "session"} {
		dir := filepath.Join(root, "internal", name)
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if name == "server" && !strings.HasPrefix(string(source), "//go:build linux\n") &&
				!strings.HasSuffix(path, "_linux.go") {
				t.Errorf("%s: Server must be Linux-only", path)
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
			if err != nil {
				return err
			}
			if f.Name.Name != name {
				t.Errorf("%s: package %s does not match the owning directory %s", path, f.Name.Name, name)
			}
			for _, imp := range f.Imports {
				target, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					return err
				}
				if strings.HasSuffix(target, "/internal/app") {
					t.Errorf("%s: obsolete app package is forbidden", path)
				}
				switch name {
				case "client":
					if strings.HasSuffix(target, "/internal/server") ||
						strings.HasSuffix(target, "/internal/xdp") ||
						strings.HasSuffix(target, "/internal/cluster") {
						t.Errorf("%s: Client imports Linux Server or HA authority %s", path, target)
					}
				case "server":
					if strings.HasSuffix(target, "/internal/client") ||
						strings.HasSuffix(target, "/internal/wintun") {
						t.Errorf("%s: Linux Server imports Client or Windows device %s", path, target)
					}
				case "session":
					for _, forbidden := range []string{"client", "server", "wan", "tun", "wintun", "routepush", "dnspush", "tcebpf", "xdp", "cluster"} {
						if strings.HasSuffix(target, "/internal/"+forbidden) {
							t.Errorf("%s: shared session imports platform or ownership component %s", path, target)
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s package: %v", name, err)
		}
	}
}

func TestCommandsImportOnlyTheirOwningRuntime(t *testing.T) {
	for _, tc := range []struct {
		name, allowed, forbidden string
	}{
		{"mqvpn-client", "/internal/client", "/internal/server"},
		{"mqvpn-server", "/internal/server", "/internal/client"},
	} {
		path := filepath.Join("..", "..", "cmd", tc.name, "main.go")
		node, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, imp := range node.Imports {
			target, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(target, tc.allowed) {
				found = true
			}
			if strings.HasSuffix(target, tc.forbidden) || strings.HasSuffix(target, "/internal/app") {
				t.Errorf("%s imports forbidden runtime %s", tc.name, target)
			}
		}
		if !found {
			t.Errorf("%s does not import its owning runtime %s", tc.name, tc.allowed)
		}
	}
}
