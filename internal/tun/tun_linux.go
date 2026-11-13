//go:build linux

package tun

import (
    "errors"
    "fmt"
    "net"
    "os"
    "syscall"
    "unsafe"
)

const (
    ifNameSize = 16
    tunSetIFF = 0x400454ca
    iffTUN = 0x0001
    iffNoPI = 0x1000
)

type ifreq struct {
    Name [ifNameSize]byte
    Flags uint16
    _ [22]byte
}

// Open attaches to an existing, externally configured TUN.
// The daemon never creates the device, assigns IP addresses, manages routes,
// or changes kernel multicast configuration.
func Open(name string) (*os.File,error) {
    if err:=validateName(name);err!=nil{return nil,err}
    nic,err:=net.InterfaceByName(name)
    if err!=nil{return nil,fmt.Errorf("TUN %q must already exist: %w",name,err)}
    if nic.Flags&net.FlagUp==0{return nil,fmt.Errorf("TUN %q must be UP before starting mqvpn",name)}
    addresses,err:=nic.Addrs()
    if err!=nil{return nil,fmt.Errorf("inspect TUN %q: %w",name,err)}
    found:=false
    for _,a:=range addresses{
        if n,ok:=a.(*net.IPNet);ok&&!n.IP.IsUnspecified()&&!n.IP.IsMulticast()&&!n.IP.IsLinkLocalUnicast(){found=true}
    }
    if !found{return nil,fmt.Errorf("TUN %q has no configured unicast IP",name)}
    f,err:=os.OpenFile("/dev/net/tun",os.O_RDWR,0)
    if err!=nil{return nil,fmt.Errorf("open /dev/net/tun: %w",err)}
    var req ifreq
    copy(req.Name[:],name)
    req.Flags=iffTUN|iffNoPI
    _,_,errno:=syscall.Syscall(syscall.SYS_IOCTL,f.Fd(),uintptr(tunSetIFF),uintptr(unsafe.Pointer(&req)))
    if errno!=0 {
        _=f.Close()
        return nil,fmt.Errorf("attach TUN %q: %w; check device type (TUN, not TAP)",name,errno)
    }
    return f,nil
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
