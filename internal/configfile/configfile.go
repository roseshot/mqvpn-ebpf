// Package configfile reads YAML configuration (and legacy JSON files).
// File extensions are explicit so CLI edits never silently change format.
package configfile

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"

    "gopkg.in/yaml.v3"
)

func isJSON(path string) bool { return strings.EqualFold(filepath.Ext(path), ".json") }

func supported(path string) bool {
    switch strings.ToLower(filepath.Ext(path)) {
    case ".yaml", ".yml", ".json": return true
    default: return false
    }
}

// Decode is strict: unknown fields, malformed data, multiple documents,
// and empty configurations fail rather than silently changing live VPNs.
func Decode(path string, raw []byte, dst any) error {
    if !supported(path) {
        return fmt.Errorf("config file %q must end with .yaml, .yml, or .json", path)
    }
    if isJSON(path) {
        dec := json.NewDecoder(bytes.NewReader(raw))
        dec.DisallowUnknownFields()
        if err:=dec.Decode(dst);err!=nil{return fmt.Errorf("decode JSON %s: %w",path,err)}
        var extra any
        if err:=dec.Decode(&extra);err==nil{return errors.New("multiple JSON documents")} else if !errors.Is(err,io.EOF){return fmt.Errorf("trailing JSON in %s: %w",path,err)}
        return nil
    }
    dec:=yaml.NewDecoder(bytes.NewReader(raw))
    dec.KnownFields(true)
    if err:=dec.Decode(dst);err!=nil{return fmt.Errorf("decode YAML %s: %w",path,err)}
    var extra any
    if err:=dec.Decode(&extra);err==nil{return errors.New("multiple YAML documents")} else if !errors.Is(err,io.EOF){return fmt.Errorf("trailing YAML in %s: %w",path,err)}
    return nil
}

func Read(path string,dst any)error{
    raw,err:=os.ReadFile(path)
    if err!=nil{return fmt.Errorf("read %s: %w",path,err)}
    return Decode(path,raw,dst)
}

func Marshal(path string,v any)([]byte,error){
    if !supported(path){return nil,fmt.Errorf("config file %q must end with .yaml, .yml, or .json",path)}
    if isJSON(path){
        data,err:=json.MarshalIndent(v,"","  ")
        if err!=nil{return nil,err}
        return append(data,'\n'),nil
    }
    return yaml.Marshal(v)
}
