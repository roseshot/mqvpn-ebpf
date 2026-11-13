package configfile

import (
    "strings"
    "testing"
)

type cfg struct {
    Name string `yaml:"name" json:"name"`
    Routes []string `yaml:"routes" json:"routes"`
}

func TestDecodeYAMLAndLegacyJSON(t *testing.T){
    for _,tc:=range []struct{path,body string}{
        {"peer.yaml","name: site-a\nroutes:\n  - 192.168.20.0/24\n"},
        {"peer.yml","name: site-b\nroutes: [192.168.20.0/24]\n"},
        {"peer.json",`{"name":"site-c","routes":["192.168.20.0/24"]}`},
    }{
        var got cfg
        if err:=Decode(tc.path,[]byte(tc.body),&got);err!=nil{t.Fatalf("%s: %v",tc.path,err)}
        if got.Name==""||len(got.Routes)!=1{t.Fatalf("bad decode: %+v",got)}
        out,err:=Marshal(tc.path,got)
        if err!=nil{t.Fatal(err)}
        var back cfg
        if err:=Decode(tc.path,out,&back);err!=nil||back.Name!=got.Name{t.Fatalf("roundtrip: %v",err)}
    }
}
func TestRejectUnknownFieldsMultipleDocsAndMalformed(t *testing.T){
    for _,tc:=range []struct{path,body string}{
        {"server.yaml","name: site-a\nunknown: forbidden\n"},
        {"server.yaml","name: first\n---\nname: second\n"},
        {"server.yaml","name: [not a scalar]\n"},
        {"server.yaml","name: x\nname: y\n"},
        {"server.json",`{"name":"x","unexpected":"y"}`},
        {"server.json",`{"name":"x"}{"name":"y"}`},
        {"server.yaml",""},
    }{
        var got cfg
        if err:=Decode(tc.path,[]byte(tc.body),&got);err==nil{t.Fatalf("accepted %s %q",tc.path,tc.body)}
    }
    if err:=Decode("unknown.toml",[]byte("name: x"),&cfg{});err==nil{t.Fatal("unsupported format accepted")}
    if _,err:=Marshal("unknown.txt",cfg{});err==nil{t.Fatal("invalid output extension accepted")}
}
func TestYAMLQuotedStrings(t *testing.T){
    out,err:=Marshal("config.yaml",cfg{Name:":4433",Routes:[]string{"0.0.0.0/0"}})
    if err!=nil{t.Fatal(err)}
    if !strings.Contains(string(out),"4433"){t.Fatal(string(out))}
    var back cfg
    if err:=Decode("config.yaml",out,&back);err!=nil||back.Name!=":4433"{t.Fatalf("failed: %+v, %v",back,err)}
}
