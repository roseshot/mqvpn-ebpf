//go:build linux

package tun

import (
  "strings"
  "testing"
)

func TestValidateName(t *testing.T) {
  for _,n:=range []string{"mq0","tun-main","tun.3"}{
    if err:=validateName(n);err!=nil{t.Fatal(n,err)}
  }
  for _,n:=range []string{"","bad name","abcdefghijklmnop","bad/name"}{
    if err:=validateName(n);err==nil{t.Fatalf("%q accepted",n)}
  }
}
func TestMissingTUNNotCreated(t *testing.T) {
  _,err:=Open("mqvp-unused-0")
  if err==nil||!strings.Contains(err.Error(),"must already exist"){t.Fatalf("got %v",err)}
}
