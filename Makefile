# Build BPF once with Clang/LLVM. Production runtime is pure Go (CGO=0).
# x86_64 header path is used for Linux UAPI types on Intel N200 systems.
CLANG ?= /usr/bin/clang
BPF_INCLUDE ?= /usr/include/x86_64-linux-gnu

.PHONY: bpf go release test fmt fmt-check mod-check modernize clean

# Packaged .o files are tracked and go:embedded in the release binaries.
# Running make bpf regenerates them from C; deployment needs only Go binaries.

bpf:
	$(CLANG) -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	  -I$(BPF_INCLUDE) -c bpf/xdp_mqvpn.c -o bpf/xdp_mqvpn.o
	$(CLANG) -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	  -I$(BPF_INCLUDE) -c bpf/tun_tc.c -o bpf/tun_tc.o
	install -D -m 0644 bpf/tun_tc.o internal/tcebpf/objects/tun_tc.o
	install -D -m 0644 bpf/xdp_mqvpn.o internal/xdp/objects/xdp_mqvpn.o

go:
	CGO_ENABLED=0 go build -mod=readonly ./cmd/...

release:
	mkdir -p bin
	CGO_ENABLED=0 go build -mod=readonly -trimpath -o bin/mqvpn-server ./cmd/mqvpn-server
	CGO_ENABLED=0 go build -mod=readonly -trimpath -o bin/mqvpn-client ./cmd/mqvpn-client

test:
	CGO_ENABLED=0 go test -mod=readonly ./...

fmt:
	gofmt -w ./cmd ./internal

fmt-check:
	@files="$(gofmt -l ./cmd ./internal)"; \
	if [ -n "$files" ]; then printf 'Go files requiring gofmt:\\n%s\\n' "$files"; exit 1; fi

mod-check:
	go mod tidy -diff
	go mod verify

# Opt-in standard-library fixers: inspect changes before committing.
modernize:
	go fix ./...
	gofmt -w ./cmd ./internal

clean:
	rm -f bpf/xdp_mqvpn.o bpf/tun_tc.o
