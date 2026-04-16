# Sandbox Runtimes

Kite Logik isolates each agent session in a container or VM. Three runtimes are available, selected by the `SANDBOX_RUNTIME` environment variable:

| Runtime | `SANDBOX_RUNTIME` value | Isolation level | Status |
|---------|------------------------|-----------------|--------|
| Docker | `docker` (default) | Namespace-based | ✅ Built |
| gVisor | `gvisor` | Syscall interception | ✅ Built |
| Firecracker | `firecracker` | Hardware/KVM | 🔲 Planned |

---

## Docker (default)

```bash
# No env var needed — Docker is the default
docker compose up -d opa
python quickstart.py
```

Each session runs in a Docker container with:
- `network_mode=none` — all egress structurally blocked
- `mem_limit=256m`, `cpu_quota=50000` (50% of one CPU), `pids_limit=64`
- `cap_drop=ALL`, `no-new-privileges:true`
- Read-only root filesystem; `/tmp` as writable tmpfs

**Limitation:** Docker uses Linux namespaces, not a separate kernel. A container escape (exploiting a Docker vulnerability) lands in the host kernel.

---

## gVisor (`runsc`)

gVisor interposes a user-space kernel between the container and the host kernel. System calls from the container never reach the host kernel directly — they are handled by gVisor's `runsc` process.

**Setup (Ubuntu/Debian):**
```bash
# Install gVisor
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt update && sudo apt install -y runsc

# Configure Docker to use runsc as a runtime
sudo runsc install
sudo systemctl restart docker

# Verify
docker run --runtime=runsc hello-world
```

**Enable in Kite Logik:**
```bash
# .env
SANDBOX_RUNTIME=gvisor
```

**Tradeoff:** gVisor adds ~2–5ms per system call compared to native Docker. Gate latency increase is minimal (gVisor is in the container lifecycle path, not the OPA evaluation path). Startup time increases by ~100–200ms per session.

---

## Firecracker MicroVM

Firecracker creates a full microVM for each session — each agent gets its own Linux kernel running inside KVM. A container escape cannot reach other sessions or the host kernel.

**Status:** Not yet implemented. Track at [GitHub Issues](https://github.com/kitelogik/kitelogik/issues).

**Planned interface:** Same `SANDBOX_RUNTIME=firecracker` env var. The `DockerRuntime` class will be joined by a `FirecrackerRuntime` class with the same interface (`spawn_sandbox`, `exec_in_sandbox`, `teardown_sandbox`).

**Requirements (when implemented):**
- Linux host with KVM support: `ls /dev/kvm`
- Firecracker binary: `apt install firecracker` or download from [firecracker-microvm/firecracker](https://github.com/firecracker-microvm/firecracker/releases)
- A rootfs image compatible with Firecracker (not a Docker image)

**Tradeoff:** ~125ms cold-start per session (vs ~500ms for Docker on first pull, ~50ms warm). Hardware isolation prevents kernel exploits from crossing session boundaries. Best for production deployments handling sensitive workloads.

---

## Choosing a runtime

| Scenario | Recommended runtime |
|----------|-------------------|
| Local development, macOS | `docker` (default) |
| Linux CI / staging | `docker` |
| Production, moderate risk | `gvisor` |
| Production, high sensitivity (finance, healthcare) | `firecracker` (when available) |
