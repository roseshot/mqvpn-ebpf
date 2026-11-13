//go:build linux && bpf_integration

package tcebpf

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// Run under CAP_BPF/CAP_SYS_ADMIN after make bpf. Uses the actual kernel
// BPF_PROG_TEST_RUN to verify packet rewriting and TCP checksum correctness.
func TestKernelTCMSSClampAndChecksum(t *testing.T) {
	object:="../../bpf/tun_tc.o"
	if _,err:=os.Stat(object);err!=nil{t.Fatalf("run make bpf before TC integration test: %v",err)}
	spec,err:=ebpf.LoadCollectionSpec(object)
	if err!=nil{t.Fatal(err)}
	col,err:=ebpf.NewCollection(spec)
	if err!=nil{t.Fatalf("kernel rejected TC eBPF object: %v",err)}
	defer col.Close()
	var key uint32
	limits,err:=EffectiveLimits(1400,"auto")
	if err!=nil{t.Fatal(err)}
	if err:=col.Maps["tun_config"].Put(key,limits);err!=nil{t.Fatal(err)}

	for _,direction:=range []string{"tc_mqvpn_ingress","tc_mqvpn_egress"}{
		p:=col.Programs[direction]
		if p==nil{t.Fatalf("%s program missing",direction)}
		for _,tc:=range []struct{desc string;packet []byte;wantMSS uint16;changed bool}{
			{"IPv4 SYN clamps",ipv4TCPSYN(1460,true,false),1360,true},
			{"IPv4 MSS below max",ipv4TCPSYN(1250,true,false),1250,false},
			{"IPv4 non-SYN unchanged",ipv4TCPSYN(1460,false,false),1460,false},
			{"IPv4 fragment never modified",ipv4TCPSYN(1460,true,true),1460,false},
			{"IPv6 SYN clamps",ipv6TCPSYN(1460),1340,true},
		}{
			outCode,out,err:=p.Test(tc.packet)
			if err!=nil{t.Fatalf("%s %s: BPF_PROG_TEST_RUN: %v",direction,tc.desc,err)}
			if outCode!=0{t.Fatalf("%s %s: TC action %d",direction,tc.desc,outCode)}
			// The BPF test run API may return zero-padded output.
			if len(out)<len(tc.packet){t.Fatalf("%s %s: short BPF output",direction,tc.desc)}
			out=out[:len(tc.packet)]
			off:=20
			if out[0]>>4==6{off=40}
			got:=binary.BigEndian.Uint16(out[off+22:off+24])
			if got!=tc.wantMSS{t.Fatalf("%s %s: MSS got %d expected %d",direction,tc.desc,got,tc.wantMSS)}
			if tc.changed {
				if gotChecksum:=transportChecksum(out,off);gotChecksum!=0{
					t.Fatalf("%s %s: checksum invalid (%04x)",direction,tc.desc,gotChecksum)
				}
			}else if !bytes.Equal(tc.packet,out) {
				t.Fatalf("%s %s: packet unexpectedly modified",direction,tc.desc)
			}
		}
	}
}

func transportChecksum(packet []byte,tcpOffset int)uint16{
	var pseudo []byte
	tcp:=packet[tcpOffset:]
	if packet[0]>>4==4{
		pseudo=make([]byte,12)
		copy(pseudo[:4],packet[12:16])
		copy(pseudo[4:8],packet[16:20])
		pseudo[9]=6
		binary.BigEndian.PutUint16(pseudo[10:12],uint16(len(tcp)))
	}else{
		pseudo=make([]byte,40)
		copy(pseudo[:16],packet[8:24])
		copy(pseudo[16:32],packet[24:40])
		binary.BigEndian.PutUint32(pseudo[32:36],uint32(len(tcp)))
		pseudo[39]=6
	}
	return checksum(append(pseudo,tcp...))
}

func checksum(b []byte)uint16{
	var sum uint32
	for i:=0;i+1<len(b);i+=2{sum+=uint32(binary.BigEndian.Uint16(b[i:i+2]))}
	if len(b)%2==1{sum+=uint32(b[len(b)-1])<<8}
	for sum>>16!=0{sum=(sum&0xffff)+(sum>>16)}
	return ^uint16(sum)
}

func makeTCP(mss uint16,syn bool)[]byte{
	tcp:=make([]byte,24)
	binary.BigEndian.PutUint16(tcp[:2],12345)
	binary.BigEndian.PutUint16(tcp[2:4],443)
	binary.BigEndian.PutUint32(tcp[4:8],1)
	tcp[12]=6<<4
	if syn{tcp[13]=2}else{tcp[13]=16}
	binary.BigEndian.PutUint16(tcp[14:16],65535)
	tcp[20]=2;tcp[21]=4
	binary.BigEndian.PutUint16(tcp[22:24],mss)
	return tcp
}
func ipv4TCPSYN(mss uint16,syn,fragment bool)[]byte{
	tcp:=makeTCP(mss,syn)
	p:=make([]byte,20+len(tcp))
	p[0]=0x45
	binary.BigEndian.PutUint16(p[2:4],uint16(len(p)))
	p[8]=64;p[9]=6
	copy(p[12:16],[]byte{10,77,0,2})
	copy(p[16:20],[]byte{10,77,0,1})
	if fragment{binary.BigEndian.PutUint16(p[6:8],0x2000)}
	binary.BigEndian.PutUint16(p[10:12],checksum(p[:20]))
	copy(p[20:],tcp)
	binary.BigEndian.PutUint16(p[36:38],transportChecksum(p,20))
	return p
}
func ipv6TCPSYN(mss uint16)[]byte{
	tcp:=makeTCP(mss,true)
	p:=make([]byte,40+len(tcp))
	p[0]=0x60
	binary.BigEndian.PutUint16(p[4:6],uint16(len(tcp)))
	p[6]=6;p[7]=64
	copy(p[8:24],[]byte{0xfd,0x77,0,0,0,0,0,0,0,0,0,0,0,0,0,2})
	copy(p[24:40],[]byte{0xfd,0x77,0,0,0,0,0,0,0,0,0,0,0,0,0,1})
	copy(p[40:],tcp)
	binary.BigEndian.PutUint16(p[56:58],transportChecksum(p,40))
	return p
}
