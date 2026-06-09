  GNU nano 9.0                                                      README.md                                                                 
#Tetragon eBPF Crypto Agent (Go)

A lightweight security agent writen in **Go** that integrates directly with **Cilium Tetragon (v1.7.0)** to provide real-time runtime monitor>

## How It Works

1. **gRPC over UDS**: The aplication establishes a low-latency connection to the Tetragon daemon via its native UNIX Domain Socket (`tetragon>
2.**eBPF Stream Consumption**: It consumes a binary gRPC event stream driven by eBPF directly from Linux kernel (Kernel 7.0)
3.**Runtime Interception**: It dynamically interepts process execution events (`ProcessExec`) the millisecond they occur in kernel space
4.**Cryptographic Validation**: The core engine hashes the binary on the fly,veryfying **SHA-256** checksums and validating **Ed25519** signa>

## Tech Stack

* **Language**:Go (Golang)
* **Kernel Observability**: eBPF via Cilium Tetragon (v1.7.0)
* **Communication Protocol**: gPRC / UNIX Domain Sockets
* **Cryptography**: SHA-256, Ed25519 signatures
* **Target Environment**: Arch Linux (Kernel 7.0+)
