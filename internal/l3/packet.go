package l3

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrInvalidIP = errors.New("malformed IPv4/IPv6 packet")

const (
	EthernetLen = 14
	ContextIDZero = byte(0)
)

// Synthetic locally administered MACs. This is an L3 overlay: MAC addresses
// only satisfy the standards-compliant CONNECT-ETHERNET Ethernet frame format.
// They are never learned, broadcast or bridged between sites.
var (
	outerDst = [6]byte{0x02, 0x6d, 0x71, 0x76, 0x70, 0x01}
	outerSrc = [6]byte{0x02, 0x6d, 0x71, 0x76, 0x70, 0x02}
)

func Inspect(pkt []byte) (src, dst netip.Addr, etherType uint16, err error) {
	if len(pkt) < 1 { return src,dst,0,ErrInvalidIP }
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt)<20 || int(pkt[0]&0x0f)<5 { return src,dst,0,ErrInvalidIP }
		hdrSize:=int(pkt[0]&0x0f)*4
		if len(pkt)<hdrSize || int(binary.BigEndian.Uint16(pkt[2:4]))!=len(pkt) {
			return src,dst,0,ErrInvalidIP
		}
		var a,b [4]byte
		copy(a[:],pkt[12:16]); copy(b[:],pkt[16:20])
		return netip.AddrFrom4(a),netip.AddrFrom4(b),0x0800,nil
	case 6:
		if len(pkt)<40 || len(pkt)!=int(binary.BigEndian.Uint16(pkt[4:6]))+40 {
			// IPv6 jumbograms are intentionally unsupported on the QUIC DATAGRAM path.
			return src,dst,0,ErrInvalidIP
		}
		var a,b [16]byte
		copy(a[:],pkt[8:24]); copy(b[:],pkt[24:40])
		return netip.AddrFrom16(a),netip.AddrFrom16(b),0x86dd,nil
	default:
		return src,dst,0,ErrInvalidIP
	}
}

// Wrap creates a standard CONNECT-ETHERNET HTTP Datagram payload:
// varint Context ID 0, dst MAC, src MAC, EtherType, complete IP packet.
// The underlying HTTP/3 library adds Quarter Stream ID.
func Wrap(pkt []byte) ([]byte,error) {
	_,_,etherType,err:=Inspect(pkt)
	if err!=nil{return nil,err}
	out:=make([]byte,1+EthernetLen+len(pkt))
	out[0]=ContextIDZero
	copy(out[1:7],outerDst[:])
	copy(out[7:13],outerSrc[:])
	binary.BigEndian.PutUint16(out[13:15],etherType)
	copy(out[15:],pkt)
	return out,nil
}

func Unwrap(payload []byte) ([]byte,error) {
	if len(payload)<1+EthernetLen+20 || payload[0]!=ContextIDZero {
		return nil,errors.New("not a CONNECT-ETHERNET context-0 IP frame")
	}
	ethType:=binary.BigEndian.Uint16(payload[13:15])
	if ethType!=0x0800 && ethType!=0x86dd {
		return nil,errors.New("non-IP Ethernet payload not allowed in L3-only tunnel")
	}
	pkt:=payload[15:]
	_,_,actual,err:=Inspect(pkt)
	if err!=nil || actual!=ethType {return nil,ErrInvalidIP}
	return pkt,nil
}

// All-multicast, broadcast and unknown-destination Ethernet frames are
// categorically excluded from this transport: it is routed, not a bridge.
// IP multicast can be handled separately by the explicit multicast service.
func IsBroadcastOrMulticastIP(ip netip.Addr) bool {
	if !ip.IsValid(){return true}
	if ip.IsMulticast() || ip.IsUnspecified(){return true}
	return ip.Is4() && ip == netip.MustParseAddr("255.255.255.255")
}
