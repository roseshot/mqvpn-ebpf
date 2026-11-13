// Package configfile provides strict YAML-only configuration.
package configfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func CheckPath(path string) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return nil
	default:
		return fmt.Errorf("configuration %q must have a .yaml or .yml extension", path)
	}
}

func Decode(path string, raw []byte, dst any) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("empty YAML configuration %q", path)
		}
		return fmt.Errorf("decode YAML %q: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return errors.New("multiple YAML documents are not supported")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing YAML in %q: %w", path, err)
	}
	return nil
}

func Read(path string, dst any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read YAML %q: %w", path, err)
	}
	return Decode(path, raw, dst)
}

func Marshal(path string, value any) ([]byte, error) {
	if err := CheckPath(path); err != nil {
		return nil, err
	}
	return yaml.Marshal(value)
}
