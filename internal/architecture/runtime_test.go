package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoRuntimeSubprocesses enforces an architectural boundary: the VPN
// daemons and their internal packages use Go libraries and Linux syscalls,
// not shell-outs to ip(8), route(8), openssl, or any other process.
//
// Development scripts, build tools, and _test.go files may invoke commands.
// This guard intentionally checks only production .go source files.
func TestNoRuntimeSubprocesses(t *testing.T) {
	root := filepath.Join("..", "..")
	production := []string{
		"internal",
		filepath.Join("cmd", "mqvpn-server"),
		filepath.Join("cmd", "mqvpn-client"),
	}
	bannedImports := map[string]bool{
		"os/exec":                true,
		"golang.org/x/sys/execabs": true,
	}
	bannedCalls := map[string]bool{
		"os.StartProcess":      true,
		"syscall.Exec":         true,
		"syscall.ForkExec":     true,
		"syscall.StartProcess": true,
	}
	for _, directory := range production {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			set := token.NewFileSet()
			node, err := parser.ParseFile(set, path, nil, 0)
			if err != nil {
				return err
			}
			for _, imp := range node.Imports {
				pkg, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					return err
				}
				if bannedImports[pkg] {
					t.Errorf("%s: production code must not import %s; use Go modules or syscalls instead", path, pkg)
				}
			}
			ast.Inspect(node, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				qualifier, ok := selector.X.(*ast.Ident)
				if !ok {
					return true
				}
				name := qualifier.Name + "." + selector.Sel.Name
				if bannedCalls[name] {
					t.Errorf("%s: %s invokes an external process in production code", set.Position(call.Pos()), name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("scan production files in %s: %v", directory, err)
		}
	}
}
