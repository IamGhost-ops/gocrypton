                                                                # Tetragon eBPF Crypto Agent (Go)

A lightweight security agent writen in **Go** that integrates directly with **Cilium Tetragon (v1.7.0)** to provide real-time runtime monitor.

## Cryptography Monitoring Environment

The architecture is split into two independent layers  to achieve full-stack observability:
1. **Application Layer (User-space)** - Intercepts business logic directly inside the compiled Go binary using Uprobes.
2. **System Layer (Kernel-space)** - Intercepts system-level operations using TOCTOU-safe LSM Hooks.

## How It Works

1. **gRPC over UDS**: The aplication establishes a low-latency connection to the Tetragon daemon via its native UNIX Domain Socket (`tetragon`)
2.**eBPF Stream Consumption**: It consumes a binary gRPC event stream driven by eBPF directly from Linux kernel (Kernel 7.0)
3.**Runtime Interception**: It dynamically interepts process execution events (`ProcessExec`) the millisecond they occur in kernel space
4.**Cryptographic Validation**: The core engine hashes the binary on the fly,veryfying **SHA-256** checksums and validating **Ed25519** signa>

## Policy Files and Details

### 1. `pro-crypto.yaml` (Uprobes)
This policy targets user-space functions inside the Go standard libraries. It captures inputs and execution for the following cryptographic primitives:
* `crypto/sha256.Sum256`- Tracks data integrity hashing operations.
* `crypto/ed25519.Sign` - Records digital signature generation.
* `crypto/ed25519.Verify` - Logs signature validation processes (public key, message, and signature).

### 2. `lsm-pro-crypto.yaml` (LSM Hooks)
This policy operates globally within the kernel space, guarding critical system cryptographic assets through secure interfaces:
* `security_key_alloc` & `security_key_permission` - Audits operations on the kernel keyring structures.
* `security_inode_permission` - Monitors and filters access attempts to system random generators (`/dev/urandom`, `/dev/random`) and hardware selectors (`/dev/crypto`).

## Tech Stack

* **Language**:Go (Golang)
* **Kernel Observability**: eBPF via Cilium Tetragon (v1.7.0)
* **Communication Protocol**: gPRC / UNIX Domain Sockets
* **Cryptography**: SHA-256, Ed25519 signatures
* **Target Environment**: Arch Linux (Kernel 7.0+)
