# Vector Production Security Architecture

**Date:** November 14, 2025
**Status:** PROPOSED
**Priority:** CRITICAL

---

## Problem Statement

Current Vector deployment listens on HTTP without authentication:
- **Endpoint:** `0.0.0.0:8686` (HTTP)
- **Authentication:** None
- **Encryption:** None
- **Security Risk:** HIGH - Anyone with network access can inject logs

**Location:** `services/detection-engine/vector/vector.toml:11`

---

## Production Architecture Options

### Option 1: TLS + API Key (Recommended)

**Best for:** Production deployments with 10-1000+ agents

#### Architecture Diagram

```
┌─────────────────────────────────────────────────┐
│ Backend Servers (Customer Infrastructure)       │
│                                                  │
│  ┌──────────────┐  ┌──────────────┐            │
│  │ Filebeat     │  │ Filebeat     │            │
│  │ Agent        │  │ Agent        │            │
│  └──────┬───────┘  └──────┬───────┘            │
│         │                  │                     │
│         │ HTTPS + API Key Header                │
│         │ X-API-Key: tenant-xyz-secret          │
│         │                                        │
└─────────┼──────────────────┼────────────────────┘
          │                  │
          │ TLS 1.3          │
          │ Encrypted        │
          ▼                  ▼
┌─────────────────────────────────────────────────┐
│ Kubernetes Cluster (SecOps AI)                  │
│                                                  │
│  ┌───────────────────────────────────────────┐  │
│  │ Load Balancer (MetalLB/AWS ALB)           │  │
│  │ - TLS termination                         │  │
│  │ - IP whitelisting                         │  │
│  │ - DDoS protection                         │  │
│  └────────┬──────────────────────────────────┘  │
│           │                                      │
│           ▼                                      │
│  ┌───────────────────────────────────────────┐  │
│  │ Vector Pods (3+ replicas)                 │  │
│  │                                           │  │
│  │  ┌─────────────────────────────────────┐ │  │
│  │  │ 1. Validate API Key                 │ │  │
│  │  │    - Query auth-service/Redis       │ │  │
│  │  │    - Extract tenant_id              │ │  │
│  │  │                                     │ │  │
│  │  │ 2. Parse & Enrich                   │ │  │
│  │  │    - GeoIP, Threat Intel            │ │  │
│  │  │    - Add tenant_id to all events    │ │  │
│  │  │                                     │ │  │
│  │  │ 3. Route to Kafka                   │ │  │
│  │  └─────────────────────────────────────┘ │  │
│  └───────────┬───────────────────────────────┘  │
│              │                                   │
│              ▼                                   │
│  ┌────────────────────────────┐                 │
│  │ Kafka (Multi-tenant)       │                 │
│  │ - security-events          │                 │
│  │ - security-auth            │                 │
│  │ - security-network         │                 │
│  │ - application-logs         │                 │
│  └────────────────────────────┘                 │
└─────────────────────────────────────────────────┘
```

#### Implementation

**1. Vector Configuration with TLS + Auth**

```toml
# /services/detection-engine/vector/vector-production.toml

# HTTP Source with TLS and API Key validation
[sources.http_logs]
type = "http_server"
address = "0.0.0.0:8686"
encoding = "json"

# TLS Configuration
[sources.http_logs.tls]
enabled = true
crt_file = "/etc/vector/tls/tls.crt"
key_file = "/etc/vector/tls/tls.key"
ca_file = "/etc/vector/tls/ca.crt"  # Optional for mTLS
verify_certificate = true           # Require valid client certs (mTLS)
verify_hostname = true

# Request headers required
[sources.http_logs.headers]
required = ["X-API-Key", "X-Tenant-ID"]

# Rate limiting per client
[sources.http_logs.framing]
method = "bytes"
max_length = 10485760  # 10MB max request

# API Key Validation Transform
[transforms.validate_api_key]
type = "remap"
inputs = ["http_logs"]
source = '''
  # Extract API key from headers
  api_key = .headers."X-API-Key" ?? ""
  tenant_id_claim = .headers."X-Tenant-ID" ?? ""

  # Validate API key (query Redis or auth-service)
  # For now, we'll use a simple hash check (replace with actual service call)

  if api_key == "" {
    log("Missing API key", level: "warn")
    abort  # Drop event
  }

  # TODO: Call auth-service to validate API key
  # validated = http_request("http://auth-service.auth:8000/validate",
  #   headers: {"Authorization": "Bearer " + api_key})

  # For MVP: Store API keys in Redis with tenant mapping
  # tenant_id = redis_get("api_key:" + api_key)

  # Temporarily accept and log
  .tenant_id = tenant_id_claim
  .api_key_validated = true
  .validation_timestamp = now()
'''
```

**2. Kubernetes TLS Secret**

```bash
# Generate self-signed cert for testing (use Let's Encrypt/cert-manager in production)
kubectl create namespace data-ingestion

# Option A: Self-signed (testing only)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /tmp/tls.key \
  -out /tmp/tls.crt \
  -subj "/CN=vector.data-ingestion.svc.cluster.local"

kubectl create secret tls vector-tls \
  --cert=/tmp/tls.crt \
  --key=/tmp/tls.key \
  -n data-ingestion

# Option B: cert-manager (production)
# Apply CertificateRequest (see cert-manager config below)
```

**3. API Key Management Service**

Create a lightweight API key validation service:

```python
# services/auth-service/src/api/api_keys.py

from fastapi import Header, HTTPException
import redis
import hashlib

redis_client = redis.Redis(host="redis-master.storage", port=6379, db=1)

async def validate_api_key(x_api_key: str = Header(...)):
    """Validate API key and return tenant_id"""

    # Hash the API key for security
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()

    # Check Redis cache
    tenant_id = redis_client.get(f"api_key:{key_hash}")

    if not tenant_id:
        # Check PostgreSQL (auth DB)
        # tenant_id = await db.query_tenant_by_api_key(key_hash)
        raise HTTPException(status_code=401, detail="Invalid API key")

    return tenant_id.decode()

# API endpoint
@app.post("/api/v1/validate-key")
async def validate_key_endpoint(x_api_key: str = Header(...)):
    tenant_id = await validate_api_key(x_api_key)
    return {"tenant_id": tenant_id, "valid": True}
```

**4. Filebeat Agent Configuration (Client-side)**

```yaml
# filebeat.yml (on customer servers)

filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/app/*.log
    fields:
      tenant_id: "customer-abc"  # Configured per customer
    fields_under_root: true

output.http:
  hosts: ["https://vector.secops-ai.com:8686"]

  # TLS Configuration
  ssl.enabled: true
  ssl.verification_mode: full
  ssl.certificate_authorities: ["/etc/filebeat/ca.crt"]  # Your CA cert

  # API Key Authentication
  headers:
    X-API-Key: "sk-customer-abc-1234567890abcdef"  # Unique per tenant
    X-Tenant-ID: "customer-abc"
    Content-Type: "application/json"

  # Connection settings
  timeout: 30
  max_retries: 3
  backoff.init: 1s
  backoff.max: 60s

  # Batching
  bulk_max_size: 2048
  compression_level: 3
```

#### Security Features

| Feature | Implementation | Status |
|---------|---------------|--------|
| **Encryption** | TLS 1.3 | ✅ |
| **Authentication** | API Key per tenant | ✅ |
| **Authorization** | Tenant isolation via API key | ✅ |
| **Rate Limiting** | Max request size (10MB) | ✅ |
| **IP Whitelisting** | LoadBalancer + NetworkPolicy | 🟡 Optional |
| **Audit Logging** | Log all auth attempts | 🟡 Recommended |
| **Key Rotation** | API key expiry/rotation | 🔴 Future |

#### Cost/Complexity

- **Complexity:** Medium
- **Setup Time:** 2-4 hours
- **Maintenance:** Low (key management)
- **Cost:** Minimal (TLS certs, Redis for caching)

---

### Option 2: Mutual TLS (mTLS) with Client Certificates

**Best for:** High-security environments, financial/healthcare

#### Architecture

```
Backend Servers
  ↓ mTLS (client cert + server cert)
  ↓ Bidirectional authentication
Vector (validates client cert CN)
  ↓
Kafka
```

#### Implementation

**Vector Configuration:**

```toml
[sources.http_logs]
type = "http_server"
address = "0.0.0.0:8686"

[sources.http_logs.tls]
enabled = true
crt_file = "/etc/vector/tls/server.crt"
key_file = "/etc/vector/tls/server.key"
ca_file = "/etc/vector/tls/ca.crt"
verify_certificate = true      # Require valid client cert
verify_hostname = false        # Allow any CN (validate in transform)

[transforms.extract_tenant_from_cert]
type = "remap"
inputs = ["http_logs"]
source = '''
  # Extract tenant from client certificate CN
  # Format: CN=tenant-customer-abc

  if exists(.tls.client_certificate.subject.common_name) {
    cn = .tls.client_certificate.subject.common_name

    # Extract tenant ID from CN
    if starts_with(cn, "tenant-") {
      .tenant_id = replace(cn, "tenant-", "")
    } else {
      log("Invalid certificate CN: " + cn, level: "error")
      abort
    }
  } else {
    log("No client certificate provided", level: "error")
    abort
  }
'''
```

**Certificate Generation:**

```bash
#!/bin/bash
# scripts/generate-mtls-certs.sh

# 1. Create CA (Certificate Authority)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/CN=SecOps-AI-CA/O=SecOps AI/C=US"

# 2. Create server certificate (Vector)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=vector.secops-ai.com/O=SecOps AI"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365

# 3. Create client certificate (per tenant)
function generate_client_cert() {
  TENANT=$1
  openssl genrsa -out "client-${TENANT}.key" 2048
  openssl req -new -key "client-${TENANT}.key" -out "client-${TENANT}.csr" \
    -subj "/CN=tenant-${TENANT}/O=SecOps AI Client"
  openssl x509 -req -in "client-${TENANT}.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out "client-${TENANT}.crt" -days 365
}

# Generate for customer-abc
generate_client_cert "customer-abc"

# Deploy to Kubernetes
kubectl create secret generic vector-mtls-server \
  --from-file=tls.crt=server.crt \
  --from-file=tls.key=server.key \
  --from-file=ca.crt=ca.crt \
  -n data-ingestion

# Distribute client certs to customers securely
```

**Filebeat Configuration (mTLS):**

```yaml
output.http:
  hosts: ["https://vector.secops-ai.com:8686"]

  ssl.enabled: true
  ssl.certificate: "/etc/filebeat/client.crt"      # Client cert
  ssl.key: "/etc/filebeat/client.key"              # Client key
  ssl.certificate_authorities: ["/etc/filebeat/ca.crt"]  # CA
  ssl.verification_mode: full
```

#### Security Features

- ✅ **Strongest authentication** (cryptographic proof)
- ✅ **Tenant isolation** via certificate CN
- ✅ **No shared secrets** (keys never transmitted)
- ✅ **Certificate revocation** via CRL/OCSP
- ❌ **Complex key distribution** (must securely send client certs)
- ❌ **Certificate lifecycle** (expiry, rotation)

#### Cost/Complexity

- **Complexity:** High
- **Setup Time:** 4-8 hours (PKI setup, cert distribution)
- **Maintenance:** Medium-High (cert rotation every 90-365 days)
- **Cost:** Low (cert-manager can automate)

---

### Option 3: Private Network + IP Whitelisting

**Best for:** All agents in same VPC/VPN, smaller deployments

#### Architecture

```
Backend Servers (VPC 10.0.0.0/16)
  ↓ VPC Peering / Site-to-Site VPN
  ↓ Private network only
Vector (Private LoadBalancer, IP whitelist)
  ↓
Kafka
```

#### Implementation

**Kubernetes NetworkPolicy:**

```yaml
# k8s/data-ingestion/vector-networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vector-ingress-whitelist
  namespace: data-ingestion
spec:
  podSelector:
    matchLabels:
      app: vector
  policyTypes:
    - Ingress
  ingress:
    # Allow only from known source IPs
    - from:
        - ipBlock:
            cidr: 10.0.0.0/16         # Customer VPC CIDR
        - ipBlock:
            cidr: 192.168.100.0/24    # On-prem network
      ports:
        - protocol: TCP
          port: 8686
```

**LoadBalancer with IP Whitelist (AWS):**

```yaml
# k8s/data-ingestion/vector-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: vector
  namespace: data-ingestion
  annotations:
    # AWS ELB IP whitelist
    service.beta.kubernetes.io/aws-load-balancer-source-ranges: "10.0.0.0/16,192.168.100.0/24"

    # Internal load balancer (not public)
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
spec:
  type: LoadBalancer
  selector:
    app: vector
  ports:
    - name: http
      port: 8686
      targetPort: 8686
      protocol: TCP
```

**Vector Configuration:**

```toml
# Still use HTTPS even on private network
[sources.http_logs]
type = "http_server"
address = "0.0.0.0:8686"

[sources.http_logs.tls]
enabled = true
crt_file = "/etc/vector/tls/tls.crt"
key_file = "/etc/vector/tls/tls.key"

# Add source IP logging for audit
[transforms.log_source_ip]
type = "remap"
inputs = ["http_logs"]
source = '''
  # Log source IP for audit trail
  .client_ip = .headers."X-Forwarded-For" ?? "unknown"
  .client_source = "private_network"

  # Still require tenant header
  if !exists(.headers."X-Tenant-ID") {
    log("Missing X-Tenant-ID header from " + .client_ip, level: "warn")
    abort
  }

  .tenant_id = .headers."X-Tenant-ID"
'''
```

#### Security Features

- ✅ **Network-level isolation** (no public exposure)
- ✅ **IP-based access control**
- ✅ **Simple to implement**
- ⚠️ **Still requires TLS** (encrypt in transit)
- ⚠️ **IP spoofing risk** (if attacker compromises VPC)
- ❌ **Not suitable for remote agents** (requires VPN for each)

#### Cost/Complexity

- **Complexity:** Low-Medium
- **Setup Time:** 1-2 hours
- **Maintenance:** Low
- **Cost:** VPN/VPC peering costs

---

## Comparison Matrix

| Criteria | TLS + API Key | mTLS | Private Network |
|----------|---------------|------|-----------------|
| **Security Level** | 🟡 Medium-High | 🟢 Highest | 🟡 Medium |
| **Setup Complexity** | 🟢 Low | 🔴 High | 🟢 Low |
| **Maintenance** | 🟢 Low | 🟡 Medium | 🟢 Low |
| **Agent Distribution** | 🟢 Easy | 🔴 Complex | 🟡 Medium |
| **Multi-Cloud Support** | 🟢 Excellent | 🟢 Excellent | 🟡 Requires VPN |
| **Compliance (SOC2, HIPAA)** | 🟢 Yes | 🟢 Yes | 🟡 Depends |
| **Recommended For** | Most use cases | Finance, Healthcare | Small/single-cloud |

---

## Recommended Implementation: TLS + API Key

### Phase 1: Enable TLS (Week 1)

1. Deploy cert-manager to Kubernetes
2. Generate TLS certificates (Let's Encrypt or self-signed)
3. Update Vector config to enable TLS
4. Test with curl

### Phase 2: API Key Validation (Week 1-2)

1. Create API key table in auth-service DB
2. Implement `/api/v1/validate-key` endpoint
3. Update Vector transform to call auth-service
4. Cache validated keys in Redis (24hr TTL)

### Phase 3: Agent Rollout (Week 2-3)

1. Generate API keys for each tenant
2. Update Filebeat configs with HTTPS + API key
3. Distribute CA certificate to agents
4. Rolling migration (test with 1 agent, then scale)

### Phase 4: Monitoring (Week 3-4)

1. Add Prometheus metrics for auth failures
2. Alert on invalid API key attempts
3. Dashboard for agent health

---

## Next Steps

1. **Decide on architecture** (recommend Option 1: TLS + API Key)
2. **Create implementation plan** (see phases above)
3. **Set up cert-manager** (if not already deployed)
4. **Implement auth-service API key validation**
5. **Update Vector configuration**
6. **Test with single agent**
7. **Roll out to production**

---

## References

- Vector TLS Docs: https://vector.dev/docs/reference/configuration/sources/http_server/
- Filebeat HTTP Output: https://www.elastic.co/guide/en/beats/filebeat/current/http-output.html
- cert-manager: https://cert-manager.io/docs/
