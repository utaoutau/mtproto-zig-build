---
description: How to build, run and deploy the MTProto Zig Proxy
---

# Deployment Workflow

This workflow documents how to build, deploy, and update the MTProto proxy, along with configuration handling.

## Building and Running

### Prerequisites
- Zig 0.15.0+
- SSH access to VPS for deployment

### Key Commands

- `make build` : Debug build (native)
- `make release` : Release build (native)
- `make release_linux` : Cross-compile for Linux
- `make test` : Run unit tests
- `make bench`  : ReleaseFast encapsulation microbench
- `make soak` : ReleaseFast 30s multithreaded soak stress
- `make deploy` : Cross-compile + stop + scp + start
- `make update-server SERVER=<ip> [VERSION=vX.Y.Z]` : Update VPS from GitHub Release

### Deployment Execution

`make deploy` performs the following steps:
1. Cross-compile for Linux.
2. `systemctl stop mtproto-proxy`.
3. `scp` binary and deploy scripts to VPS.
4. If `$(CONFIG)` exists locally, upload it as `/opt/mtproto-proxy/config.toml`.
5. `systemctl start mtproto-proxy`.

> [!IMPORTANT]
> You must stop the service before using `scp` because the systemd unit has `ReadOnlyPaths=/opt/mtproto-proxy`, which prevents overwriting the binary while it is running.

## Server Update Path (Recommended for Operators)

For routine production upgrades, users should update from GitHub Releases instead of rebuilding on the VPS.

### Local orchestrated update
```bash
make update-server SERVER=<SERVER_IP>
make update-server SERVER=<SERVER_IP> VERSION=v0.1.0
```

This runs `deploy/update.sh` remotely over SSH.

### Direct update on the VPS
```bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/update.sh | sudo bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/update.sh | sudo bash -s -- v0.1.0
```

### Update safety guarantees
- Detects server architecture (`x86_64`/`aarch64`) and downloads matching release artifact.
- Stops `mtproto-proxy`, installs new binary, updates deploy helper scripts and service unit.
- Preserves runtime state (`/opt/mtproto-proxy/config.toml`, `/opt/mtproto-proxy/env.sh`).
- Creates timestamped backup of current binary before replacement.
- Automatically rolls back to previous binary if restart fails.

### Operator rollback
If needed, restore the backup binary printed by `update.sh` and restart:
```bash
sudo cp /opt/mtproto-proxy/mtproto-proxy.backup.<timestamp> /opt/mtproto-proxy/mtproto-proxy
sudo systemctl restart mtproto-proxy
```

## Systemd Unit (`deploy/mtproto-proxy.service`)
Key performance and security settings:
- `LimitNOFILE=65535`: Enough file descriptors for thousands of concurrent connections.
- `TasksMax=65535`: Enough threads for the one-thread-per-connection model.
- `ReadOnlyPaths=/opt/mtproto-proxy`: Security hardening.

## Release Workflow (GitHub)
- Release automation is handled by `release-please` in `.github/workflows/release-please.yml`.
- It updates/opens one release PR, not one release per commit.
- A real GitHub release is created only when the release PR is merged.
- Bump policy follows Conventional Commits:
  - `fix:` -> patch
  - `feat:` -> minor
  - `BREAKING CHANGE:` / `!` -> major
- To keep required checks compatible with release PRs, repository secret `RELEASE_PLEASE_TOKEN` must be set (PAT with `Contents`, `Pull requests`, `Issues` read/write for this repo).
