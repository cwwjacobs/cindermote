# Unresolved Risks & Known Limitations

1. **Hardware / Host Isolation Gate**: In containerized environments lacking `/dev/kvm`, live Firecracker VM detonation cannot execute and returns `INFRASTRUCTURE_FAILED` or `SKIPPED`. Full hardware containment requires a bare-metal Linux 6.18 host with `/dev/kvm` enabled and host swap disabled.
2. **Provider Side-Channel & Data Retention**: External model endpoints (e.g. OpenAI/DeepSeek) receive prompt text inside TLS tunnels. Content retention or logging by third-party model providers remains an external risk outside Cindermote's local kernel boundary.
3. **Multi-Tenant SaaS Control Plane**: The control plane (web UI, multi-tenant billing, OAuth) is out of scope for the core kernel spine and must be isolated from raw guest semantic relay paths when built.
