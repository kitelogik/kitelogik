# OPA Bundle Distribution Guide

In development, Kite Logik runs OPA locally with `--watch` so policies reload on file save. In production, you should run OPA as a standalone service and distribute policies as **bundles** — signed, versioned tarballs that OPA pulls from a bundle server.

This guide covers:
1. [Why bundles](#why-bundles)
2. [Running OPA as a standalone service](#running-opa-as-a-standalone-service)
3. [Setting up a bundle server](#setting-up-a-bundle-server)
4. [Signing bundles for integrity](#signing-bundles-for-integrity)
5. [Configuring Kite Logik to use a remote OPA](#configuring-kite-logik-to-use-a-remote-opa)
6. [Clustered OPA](#clustered-opa)
7. [Policy deployment workflow](#policy-deployment-workflow)

---

## Why bundles

| Approach | Development | Production |
|----------|-------------|------------|
| `--watch` on local files | ✅ Simple | ❌ Not replicated across nodes |
| Bundle server | ❌ More setup | ✅ Atomic, signed, replicated |

Bundles give you:
- **Atomic rollout** — all OPA instances switch to the new policy at the same time
- **Version tracking** — every bundle has a `revision` field; OPA includes it in decisions
- **Cryptographic integrity** — OPA rejects bundles that fail signature verification
- **Auditability** — Kite Logik records `policy_version` (the bundle revision) in every audit record

---

## Running OPA as a standalone service

```yaml
# docker-compose.yml — production OPA service
services:
  opa:
    image: openpolicyagent/opa:latest
    command:
      - run
      - --server
      - --addr=0.0.0.0:8181
      - --config-file=/config/opa-config.yaml
      - --log-format=json
      - --log-level=info
    volumes:
      - ./opa-config.yaml:/config/opa-config.yaml:ro
      - ./opa-keys:/keys:ro          # signing keys
    ports:
      - "8181:8181"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8181/health"]
      interval: 10s
      timeout: 5s
      retries: 3
```

---

## Setting up a bundle server

Any HTTP server that serves a tarball at a stable URL works. Common choices:

### Option A — S3 (recommended for AWS)

```bash
# Build the bundle
opa build kitelogik/policies/ -o bundle.tar.gz

# Upload to S3
aws s3 cp bundle.tar.gz s3://my-org-opa-bundles/kitelogik/bundle.tar.gz
```

OPA config:
```yaml
# opa-config.yaml
bundles:
  kitelogik:
    resource: s3://my-org-opa-bundles/kitelogik/bundle.tar.gz
    polling:
      min_delay_seconds: 60
      max_delay_seconds: 120
    signing:
      keyid: kitelogik-prod

services:
  s3:
    url: https://s3.amazonaws.com
    credentials:
      s3_signing:
        environment_credentials: {}
```

### Option B — GCS

```yaml
services:
  gcs:
    url: https://storage.googleapis.com
    credentials:
      gcp_metadata:
        scopes:
          - https://www.googleapis.com/auth/devstorage.read_only

bundles:
  kitelogik:
    resource: /storage/v1/b/my-org-opa-bundles/o/bundle.tar.gz?alt=media
    service: gcs
    polling:
      min_delay_seconds: 60
      max_delay_seconds: 120
```

### Option C — nginx (simple self-hosted)

```nginx
server {
    listen 8888;
    location /bundles/ {
        root /var/opa;
        autoindex off;
    }
}
```

```yaml
# opa-config.yaml
services:
  bundle-server:
    url: http://bundle-server:8888

bundles:
  kitelogik:
    service: bundle-server
    resource: /bundles/bundle.tar.gz
    polling:
      min_delay_seconds: 30
      max_delay_seconds: 60
```

---

## Signing bundles for integrity

OPA verifies bundle signatures using RS256 (RSA-SHA256). This prevents a compromised bundle server from serving malicious policies.

```bash
# Generate a signing key pair (do this once; store private key in a secret manager)
openssl genrsa -out opa-signing.pem 2048
openssl rsa -in opa-signing.pem -pubout -out opa-signing-pub.pem

# Build and sign the bundle
opa build kitelogik/policies/ \
  -o bundle.tar.gz \
  --signing-key opa-signing.pem \
  --signing-alg RS256 \
  --bundle-verification-key-id kitelogik-prod
```

OPA config — tell OPA to verify with the public key:
```yaml
keys:
  kitelogik-prod:
    algorithm: RS256
    key: |
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
      -----END PUBLIC KEY-----

bundles:
  kitelogik:
    resource: /bundles/bundle.tar.gz
    signing:
      keyid: kitelogik-prod
      scope: write
```

OPA will now reject any bundle not signed by the corresponding private key.

---

## Configuring Kite Logik to use a remote OPA

Set `OPA_BASE_URL` to point at your OPA service:

```bash
# .env
OPA_BASE_URL=http://opa.internal:8181
```

Or in docker-compose:
```yaml
services:
  kitelogik:
    environment:
      OPA_BASE_URL: http://opa:8181
```

Kite Logik's `OPAClient` reads this at startup. The `PolicyGate` is fail-closed — if OPA is unreachable, every tool call returns `deny=True, risk_tier=SECURITY_CRITICAL`. This means a bundle server outage does not leave agents ungoverned; it halts them.

---

## Clustered OPA

For high availability, run OPA as a Kubernetes deployment behind a service:

```yaml
# kubernetes/opa-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opa
spec:
  replicas: 3
  selector:
    matchLabels: {app: opa}
  template:
    metadata:
      labels: {app: opa}
    spec:
      containers:
        - name: opa
          image: openpolicyagent/opa:latest
          args:
            - run
            - --server
            - --addr=0.0.0.0:8181
            - --config-file=/config/opa-config.yaml
            - --log-format=json
          volumeMounts:
            - name: config
              mountPath: /config
              readOnly: true
          readinessProbe:
            httpGet: {path: /health, port: 8181}
            initialDelaySeconds: 5
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits:   {cpu: 500m, memory: 256Mi}
      volumes:
        - name: config
          configMap: {name: opa-config}
---
apiVersion: v1
kind: Service
metadata:
  name: opa
spec:
  selector: {app: opa}
  ports:
    - port: 8181
      targetPort: 8181
```

Set `OPA_BASE_URL=http://opa:8181` in the Kite Logik deployment. Kubernetes round-robins requests across all three OPA replicas.

Each replica independently polls the bundle server. All replicas converge on the same policy within one polling interval after a bundle is published.

---

## Policy deployment workflow

A safe workflow for updating Rego policies in production:

```
1. Edit policies/*.rego locally
2. opa test kitelogik/policies/ -v          ← must pass; CI gate
3. opa fmt --write kitelogik/policies/      ← auto-format
4. git commit && git push
5. CI runs: opa test kitelogik/policies/ -v, opa build kitelogik/policies/ -o bundle.tar.gz
6. CI uploads signed bundle to bundle server (S3/GCS/nginx)
7. OPA instances detect new bundle within min_delay_seconds (60s default)
8. OPA loads and validates bundle signature
9. Audit records written after the rollover include the new bundle revision
```

To verify a rollout succeeded:
```bash
# Check which bundle revision OPA is running
curl http://opa:8181/v1/data/system/bundle | jq '.result.kitelogik.metadata.revision'

# Should match the revision in your latest bundle
```

To roll back, re-upload the previous signed bundle to the bundle server. OPA will pick it up on the next poll.
