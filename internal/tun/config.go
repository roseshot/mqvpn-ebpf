package tun

import (
	"errors"
	"fmt"
	"net/netip"
)

const (
	ifNameSize = 16
	DefaultMTU = 1400
	EthernetOverhead = 14
)

// ValidateAddress ensures a routable unicast host CIDR is supplied, not
// a network address inferred from a peer's route, subnet or VPN instance.
func ValidateAddress(cidr string, mtu, maxFrame int) error {
	prefix,err:=netip.ParsePrefix(cidr)
	if err!=nil {return fmt.Errorf("TUN address %q must be an IP/CIDR (e.g. 10.77.0.1/24): %w",cidr,err)}
	ip:=prefix.Addr()
	if ip.Is4In6()||ip.IsUnspecified()||ip.IsMulticast()||ip.IsLoopback()||ip.IsLinkLocalUnicast(){
		return fmt.Errorf("TUN address %q must be a non-link-local unicast IP",cidr)
	}
	minMTU:=576
	if ip.Is6() {minMTU=1280}
	if mtu<minMTU || mtu>65535 {
		return fmt.Errorf("TUN MTU %d must be between %d and 65535 for %s",mtu,minMTU,cidr)
	}
	if maxFrame>0 && mtu+EthernetOverhead>maxFrame {
		return fmt.Errorf("TUN MTU %d with Ethernet overhead exceeds max-frame %d",mtu,maxFrame)
	}
	return nil
}

func Validate(name,cidr string,mtu,maxFrame int)error{
	if err:=validateName(name);err!=nil{return err}
	return ValidateAddress(cidr,mtu,maxFrame)
}

func validateName(name string)error{
	if name==""||len(name)>=ifNameSize{return errors.New("TUN name must contain 1..15 ASCII characters")}
	for _,c:=range []byte(name){
		if !(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='_'||c=='-'||c=='.'){
			return fmt.Errorf("invalid TUN name %q",name)
		}
	}
	return nil
}
