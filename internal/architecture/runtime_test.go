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
// daemons use Go libraries and Linux syscalls, not general shell-outs.
// The only exception is direct resolvconf invocation for interface DNS
// when systemd-resolved is absent; resolvconf has no standard socket or
// D-Bus API. No shell, command templates, or other external tools allowed.
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
	// This one path may use os/exec to invoke only the checked
	// resolvconf binary. All other production code remains subprocess-free.
	allowedResolvconf := filepath.Join(root, "internal", "dnspush", "resolvconf_linux.go")
	bannedImports := map[string]bool{
		"os/exec":                  true,
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
				if bannedImports[pkg] && !(path == allowedResolvconf && pkg == "os/exec") {
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
				// Only the DNS fallback may use the direct exec package.
				// Any other use or any other executable-launching method
				// requires an explicit architecture review.
				if qualifier.Name == "exec" && (selector.Sel.Name == "Command" ||
					selector.Sel.Name == "CommandContext" || selector.Sel.Name == "LookPath") {
					if path != allowedResolvconf || selector.Sel.Name == "Command" {
						t.Errorf("%s: unsupported process invocation %s", set.Position(call.Pos()), name)
					}
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

// TestProductionLoggingUsesSlog rejects accidental divergence from the
// common logging package. The only stdout print exception produces YAML
// data for the "instance list" CLI; it is not a diagnostic log.
func TestProductionLoggingUsesSlog(t *testing.T) {
	root := filepath.Join("..", "..")
	allowedDataOutput := filepath.Join(root, "internal", "server", "cli_linux.go")
	for _, directory := range []string{"internal", filepath.Join("cmd", "mqvpn-server"), filepath.Join("cmd", "mqvpn-client")} {
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
			ast.Inspect(node, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				name := pkg.Name + "." + sel.Sel.Name
				banned := name == "slog.Default" ||
					strings.HasPrefix(name, "log.Print") || strings.HasPrefix(name, "log.Fatal") ||
					name == "log.Panic" || name == "fmt.Print" || name == "fmt.Println" ||
					name == "fmt.Fprint" || name == "fmt.Fprintln"
				if name == "fmt.Println" && path == allowedDataOutput {
					banned = false
				}
				if banned {
					t.Errorf("%s: unstructured or global logging %s; use the injected slog.Logger", set.Position(call.Pos()), name)
				}
				if name == "fmt.Fprintf" && len(call.Args) > 0 {
					if target, ok := call.Args[0].(*ast.SelectorExpr); ok {
						if v, ok := target.X.(*ast.Ident); ok && v.Name == "os" && (target.Sel.Name == "Stderr" || target.Sel.Name == "Stdout") {
							t.Errorf("%s: direct stdout/stderr diagnostic output; use slog", set.Position(call.Pos()))
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("scan production logging in %s: %v", directory, err)
		}
	}
}
