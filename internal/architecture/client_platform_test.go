package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestClientEntryPointsUsePlatform ensures future native adapters can replace
// OS-owned underlay and tunnel resources without forking the QUIC/TCP Client.
// Linux syscalls are permitted in client_platform_linux.go and the Linux
// network resource implementation, not in the shared session orchestrators.
func TestClientEntryPointsUsePlatform(t *testing.T) {
	for _, name := range []string{"cli.go", "tcp.go", "sticky.go"} {
		path := filepath.Join("..", "client", name)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			pkg, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(pkg, "/internal/wan") || strings.HasSuffix(pkg, "/internal/tun") {
				t.Errorf("%s imports Linux device code %s; use networkPlatform instead", path, pkg)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if direct, ok := call.Fun.(*ast.Ident); ok && direct.Name == "openClientNetworkSession" {
				t.Errorf("%s calls the Linux network session directly", fset.Position(call.Pos()))
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			direct := pkg.Name + "." + sel.Sel.Name
			if direct == "routepush.ProtectServer" || direct == "dnspush.Apply" ||
				direct == "tun.OpenClient" || direct == "wan.Listen" ||
				direct == "wan.ResolveSource" || direct == "wan.DialTCP" ||
				direct == "wan.SourceUnderlay" {
				t.Errorf("%s bypasses Client platform boundary: %s", fset.Position(call.Pos()), direct)
			}
			return true
		})
	}
}
