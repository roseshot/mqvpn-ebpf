# Build BPF once with Clang/LLVM. Production runtime is pure Go (CGO=0).
# x86_64 header path is used for Linux UAPI types on Intel N200 systems.
CLANG ?= /usr/bin/clang
BPF_INCLUDE ?= /usr/include/x86_64-linux-gnu

.PHONY: bpf go test clean

bpf:
	$(CLANG) -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	  -I$(BPF_INCLUDE) -c bpf/xdp_mqvpn.c -o bpf/xdp_mqvpn.o
	$(CLANG) -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	  -I$(BPF_INCLUDE) -c bpf/tun_tc.c -o bpf/tun_tc.o

go:
	CGO_ENABLED=0 go build -mod=mod ./cmd/...

test:
	CGO_ENABLED=0 go test -mod=mod ./...

clean:
	rm -f bpf/xdp_mqvpn.o bpf/tun_tc.o
