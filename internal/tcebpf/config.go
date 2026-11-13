package tcebpf

import (
	"fmt"
	"strconv"
	"strings"
)

// Empty object selects the ELF embedded in the Go executable.
// A non-empty object overrides the embedded program with a local ELF path.
const DefaultObject = ""

// Config controls per-TUN TCX processing. Auto falls back to ordinary TUN
// forwarding when the kernel, permissions, or program load is unavailable.
type Config struct {
	Mode     string `yaml:"mode,omitempty"` // off | auto | required
	Object   string `yaml:"object,omitempty"`
	MSSClamp string `yaml:"mss_clamp,omitempty"`
	Stats    bool   `yaml:"stats,omitempty"`
}

func DefaultConfig() Config {
	return Config{Mode: "auto", Object: DefaultObject, MSSClamp: "auto", Stats: true}
}
func (c Config) Enabled() bool { return c.Mode == "auto" || c.Mode == "required" }

// Legacy object-based opt-in remains fail-closed as "required".
func (c Config) Normalize() (Config, error) {
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	c.Object = strings.TrimSpace(c.Object)
	c.MSSClamp = strings.ToLower(strings.TrimSpace(c.MSSClamp))
	switch c.Mode {
	case "":
		if c.Object == "" {
			if (c.MSSClamp != "" && c.MSSClamp != "off") || c.Stats {
				return Config{}, fmt.Errorf("TUN TC eBPF object is required for mss_clamp=%s or stats", c.MSSClamp)
			}
			return Config{Mode: "off", MSSClamp: "off"}, nil
		}
		c.Mode = "required"
		if c.MSSClamp == "" { c.MSSClamp = "off" }
	case "off":
		return Config{Mode: "off", MSSClamp: "off"}, nil
	case "auto", "required":
		if c.MSSClamp == "" { c.MSSClamp = "auto" }
	default:
		return Config{}, fmt.Errorf("invalid TC eBPF mode %q (off|auto|required)", c.Mode)
	}
	if c.MSSClamp != "off" && c.MSSClamp != "auto" {
		v, err := strconv.Atoi(c.MSSClamp)
		if err != nil || v < 256 || v > 65535 {
			return Config{}, fmt.Errorf("invalid mss_clamp %q (off|auto|256..65535)", c.MSSClamp)
		}
	}
	return c, nil
}

type Limits struct {
	MTU   uint32
	MSS4  uint16
	MSS6  uint16
	Clamp uint32
	Stats uint32
}

// EffectiveLimits never increases the MTU-derived TCP MSS limit.
func EffectiveLimits(mtu int, raw string) (Limits, error) {
	if mtu < 576 || mtu > 65535 { return Limits{}, fmt.Errorf("invalid TUN MTU %d", mtu) }
	c, err := (Config{Object: "enabled", MSSClamp: raw}).Normalize()
	if err != nil { return Limits{}, err }
	r := Limits{MTU: uint32(mtu)}
	if c.MSSClamp == "off" { return r, nil }
	v4, v6 := mtu-40, mtu-60
	if v4 <= 0 || v6 <= 0 { return Limits{}, fmt.Errorf("invalid TUN MTU %d for TCP MSS", mtu) }
	if c.MSSClamp != "auto" {
		target, _ := strconv.Atoi(c.MSSClamp)
		if v4 > target { v4 = target }
		if v6 > target { v6 = target }
	}
	r.MSS4, r.MSS6, r.Clamp = uint16(v4), uint16(v6), 1
	return r, nil
}
