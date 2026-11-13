package app

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// validateMasquePath enforces a canonical absolute path with no request
// query, fragment, CRLF, percent-encoded delimiters or dot-segment
// ambiguity. Both Server and Client use the same exact string.
func validateMasquePath(path string)error{
	if path=="" || len(path)>1024 || !utf8.ValidString(path) || path[0]!='/' {
		return errors.New("MASQUE path must be an absolute URL path (1..1024 bytes)")
	}
	if strings.HasPrefix(path,"//") || strings.Contains(path,"//") {
		return fmt.Errorf("MASQUE path %q contains duplicate slashes",path)
	}
	for _,c:=range path {
		if c<=' ' || c==127 || c=='?' || c=='#' || c=='%' || c=='\\' {
			return fmt.Errorf("MASQUE path %q contains unsafe delimiter/escape",path)
		}
	}
	for _,seg:=range strings.Split(path,"/"){
		if seg=="." || seg==".." {
			return fmt.Errorf("MASQUE path %q contains dot segment",path)
		}
	}
	return nil
}
