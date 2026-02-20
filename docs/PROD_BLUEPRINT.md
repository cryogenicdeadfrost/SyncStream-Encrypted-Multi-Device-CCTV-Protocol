# Production Blueprint

## Architecture

- Mobile camera client captures frames and sends media via SRTP/WebRTC stack
- Control plane uses SyncStream RelayCore envelopes over TLS websocket or gRPC stream
- Relay service validates replay, skew, and AEAD integrity before acting on commands
- Device registry stores per-device policy, rate limits, and key version metadata

## Runtime topology

- Edge relay pods in Kubernetes with horizontal autoscaling
- Redis for distributed replay-key cache if multiple relay replicas handle same device
- PostgreSQL for device enrollment, audit logs, and policy snapshots
- OpenTelemetry for traces, metrics, structured logs

## Security profile

- Rotate symmetric control keys using key version id and staged rollout
- Enforce mTLS between mobile gateways and relay ingress
- Pin TLS certs on mobile apps
- Store keys in KMS/HSM-backed secret providers
- Use short skew windows and replay caps tuned per traffic rate

## Delivery profile

- Build with strict warning mode enabled
- Run unit tests and fuzz harnesses in CI
- Run dependency scanning and SAST on every merge
- Gate release with canary deployment and synthetic control-path probes
