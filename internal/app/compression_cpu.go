package app

import (
	"runtime"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Compression is an optional optimization. Avoid spending scarce CPU time on
// Zstd where it could increase latency for SIP/RTP and other interactive data.
//
// These conservative startup thresholds are deliberately independent of CPU
// model names or /proc/cpuinfo, which do not predict performance reliably.
const (
	minCompressionWorkers    = 4
	minCompressionMiBPerSec  = 100.0
	compressionProbePackets  = 1024
	compressionProbeMaxTime  = 100 * time.Millisecond
	compressionProbeFrameLen = 1400
)

type cpuCompressionProfile struct {
	enabled       bool
	cpus          int
	gomaxprocs    int
	throughputMiB float64
}

var localCompressionProfile = sync.OnceValue(detectCompressionCPU)

// compressionCPUAllowed is separate from the benchmark for deterministic
// tests. A process with fewer than four usable schedulers remains uncompressed
// even if an idle-core microbenchmark is fast.
func compressionCPUAllowed(cpus, gomaxprocs int, throughputMiB float64) bool {
	return cpus >= minCompressionWorkers &&
		gomaxprocs >= minCompressionWorkers &&
		throughputMiB >= minCompressionMiBPerSec
}

func detectCompressionCPU() cpuCompressionProfile {
	p := cpuCompressionProfile{cpus: runtime.NumCPU(), gomaxprocs: runtime.GOMAXPROCS(0)}
	if p.cpus < minCompressionWorkers || p.gomaxprocs < minCompressionWorkers {
		return p
	}
	throughput, err := measureZstdThroughput()
	if err != nil {
		return p // Benchmark failure is fail-closed: no compression.
	}
	p.throughputMiB = throughput
	p.enabled = compressionCPUAllowed(p.cpus, p.gomaxprocs, throughput)
	return p
}

func localCompressionAvailable() bool {
	return localCompressionProfile().enabled
}

// measureZstdThroughput performs one bounded, per-process startup probe.
// The input contains both repetitive and pseudorandom data to avoid testing
// only all-zero packets. Compression runs on one worker, matching Codec.
func measureZstdThroughput() (float64, error) {
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithEncoderConcurrency(1))
	if err != nil {
		return 0, err
	}
	defer encoder.Close()

	var sample [compressionProbeFrameLen]byte
	var rng uint32 = 0x9e3779b9
	for i := range sample {
		if i%64 < 32 {
			sample[i] = byte(i % 8)
			continue
		}
		rng ^= rng << 13
		rng ^= rng >> 17
		rng ^= rng << 5
		sample[i] = byte(rng)
	}
	output := make([]byte, 0, len(sample))
	output = encoder.EncodeAll(sample[:], output)
	start := time.Now()
	count := 0
	for count < compressionProbePackets {
		output = encoder.EncodeAll(sample[:], output[:0])
		count++
		if count%128 == 0 && time.Since(start) >= compressionProbeMaxTime {
			break
		}
	}
	elapsed := time.Since(start)
	if elapsed <= 0 {
		return 0, nil
	}
	bytesPerSecond := float64(count*len(sample)) / elapsed.Seconds()
	return bytesPerSecond / (1 << 20), nil
}
