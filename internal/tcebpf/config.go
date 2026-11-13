package tcebpf

import (
	"fmt"
	"strconv"
	"strings"
)

// Config enables optional TUN TCX processing. All fields are per VPN instance.
// No BPF program is attached if Object is omitted and Clamp/Stats are disabled.
type Config struct {
	Object string `yaml:"object,omitempty"`
	MSSClamp string `yaml:"mss_clamp,omitempty"`
	Stats bool `yaml:"stats,omitempty"`
}

func (c Config) Enabled() bool {return c.Object!=""}

// Normalize validates configuration without accessing the kernel or files.
// The feature is opt-in: without an explicit object and policy, no TCX
// program is attached.
func (c Config) Normalize() (Config,error) {
	c.MSSClamp=strings.ToLower(strings.TrimSpace(c.MSSClamp))
	if c.MSSClamp=="" {c.MSSClamp="off"}
	if c.Object=="" {
		if c.MSSClamp!="off" || c.Stats {
			return Config{},fmt.Errorf("TUN TC eBPF object is required for mss_clamp=%s or stats",c.MSSClamp)
		}
		return Config{},nil
	}
	if c.MSSClamp!="off" && c.MSSClamp!="auto" {
		v,err:=strconv.Atoi(c.MSSClamp)
		if err!=nil || v<256 || v>65535 {
			return Config{},fmt.Errorf("invalid mss_clamp %q (off|auto|256..65535)",c.MSSClamp)
		}
	}
	return c,nil
}

type Limits struct {
	MTU uint32
	MSS4 uint16
	MSS6 uint16
	Clamp uint32
}

// EffectiveLimits computes maximum inner TCP MSS from the actual TUN MTU.
// Even explicit values may only LOWER the MTU-derived limit; never increase it.
func EffectiveLimits(mtu int,raw string)(Limits,error) {
	if mtu<576||mtu>65535{return Limits{},fmt.Errorf("invalid TUN MTU %d",mtu)}
	c,err:=(Config{Object:"enabled",MSSClamp:raw}).Normalize()
	if err!=nil{return Limits{},err}
	r:=Limits{MTU:uint32(mtu)}
	if c.MSSClamp=="off"{return r,nil}
	v4,v6:=mtu-40,mtu-60
	if v4<=0 || v6<=0 {return Limits{},fmt.Errorf("invalid TUN MTU %d for TCP MSS",mtu)}
	if c.MSSClamp!="auto" {
		target,_:=strconv.Atoi(c.MSSClamp)
		if v4>target {v4=target}
		if v6>target {v6=target}
	}
	r.MSS4=uint16(v4)
	r.MSS6=uint16(v6)
	r.Clamp=1
	return r,nil
}
