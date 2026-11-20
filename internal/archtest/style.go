package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
)

// checkDeclarationStyle covers declarations, including tests and fixtures.
// Function signatures and multi-value assignments retain ordinary Go syntax.
func checkDeclarationStyle(name string, source []byte) []string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, source, parser.ParseComments)
	if err != nil {
		return []string{fmt.Sprintf("%s: STYLE_PARSE: %v", name, err)}
	}
	var violations []string
	report := func(pos token.Pos) {
		violations = append(violations, fmt.Sprintf("%s: STYLE_DECLARATION: put each struct field and var/const name on its own declaration line", fset.Position(pos)))
	}
	declarations := map[int]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.StructType:
			previous := 0
			for _, field := range n.Fields.List {
				line := fset.Position(field.Pos()).Line
				if len(field.Names) > 1 || line == previous {
					report(field.Pos())
				}
				previous = fset.Position(field.End()).Line
			}
		case *ast.ValueSpec:
			line := fset.Position(n.Pos()).Line
			if len(n.Names) > 1 || declarations[line] {
				report(n.Pos())
			}
			declarations[line] = true
		}
		return true
	})
	return violations
}
