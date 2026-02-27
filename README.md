# CKS Practice Pack #2026

This repository contains a collection of practical, hands-on scenarios designed to help you prepare for the **Certified Kubernetes Security Specialist (CKS)** exam ☸️

These exercises are built for a self-hosted `kubeadm` cluster (e.g., running on Proxmox with Istio/Cilium) and cover the core domains of the CKS curriculum, from cluster setup and hardening to runtime security.

This entire repository consists of summarys from Killerkoda/KodeKloud and a lot of mockexam questions. Best of luck! :) 
```yaml
# Allow frontend to receive external traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-ingress
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: frontend
  policyTypes:
  - Ingress
  ingress:
  - {}  # Allow from anywhere (ingress controller will handle this)
---
# Allow backend to receive traffic only from frontend
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-ingress
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: frontend
    ports:
    - protocol: TCP
      port: 8080
---
# Allow database to receive traffic only from backend
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-ingress
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: backend
    ports:
    - protocol: TCP
      port: 5432
```

### The DNS egress trap:

When you create an egress policy, you must explicitly allow DNS resolution, or pods cannot resolve service names. This catches many candidates off-guard.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
```

### Verification commands:

```bash
# List all network policies across all namespaces
kubectl get networkpolicy -A

# Detailed view of specific policy
kubectl describe networkpolicy <policy-name> -n <namespace>

# Test connectivity (from within a pod)
kubectl exec -it <source-pod> -- curl --max-time 2 <target-service>:<port>
kubectl exec -it <source-pod> -- wget -qO- --timeout=2 <target-service>:<port>

# If curl/wget unavailable, use nc
kubectl exec -it <source-pod> -- nc -zv <target-ip> <port>
```

> **Exam tip:** Always test your policies. A syntactically correct policy that doesn't match the right pods provides no protection. Verify with actual connectivity tests.

## CIS Benchmarks and kube-bench: Auditing Cluster Security

The Center for Internet Security (CIS) publishes comprehensive benchmarks for securing Kubernetes components. These benchmarks represent industry consensus on secure configurations, covering everything from file permissions to API server flags. The kube-bench tool automates these checks, providing a systematic audit of your cluster's security posture.

**Why CIS benchmarks matter:** Default Kubernetes installations prioritize ease of use over security. Anonymous authentication enabled, insecure ports open, overly permissive file permissions—these defaults create attack vectors that CIS benchmarks help identify and remediate.

### Running kube-bench:

```bash
# Auto-detect cluster type and run all checks
kube-bench run

# Target specific components
kube-bench run --targets master    # Control plane checks
kube-bench run --targets node      # Worker node checks
kube-bench run --targets etcd      # etcd-specific checks

# Run as a Kubernetes Job (useful when direct access is limited)
kubectl apply -f [https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml](https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml)
kubectl logs -f job/kube-bench
```

### Interpreting kube-bench output:

Results are categorized as:
* `[PASS]`: Configuration meets benchmark requirements
* `[FAIL]`: Configuration violates benchmark, remediation needed
* `[WARN]`: Manual verification required
* `[INFO]`: Informational, no action required

Focus on **FAIL** results first; these are the items exam questions typically ask you to remediate.

### Critical file paths you must know:

| Component | Configuration File | Purpose |
| :--- | :--- | :--- |
| API Server | `/etc/kubernetes/manifests/kube-apiserver.yaml` | Control plane API configuration |
| Controller Manager | `/etc/kubernetes/manifests/kube-controller-manager.yaml` | Controller configurations |
| Scheduler | `/etc/kubernetes/manifests/kube-scheduler.yaml` | Scheduling decisions |
| etcd | `/etc/kubernetes/manifests/etcd.yaml` | Distributed key-value store |
| Kubelet | `/var/lib/kubelet/config.yaml` | Node agent configuration |
| PKI Certificates | `/etc/kubernetes/pki/` | Cluster certificates and keys |
| etcd Data | `/var/lib/etcd/` | etcd persistent storage |

### Common CIS failures and remediations:

**Anonymous authentication enabled (API Server):**
By default, unauthenticated requests are assigned to the `system:anonymous` user. Attackers use this to probe API capabilities.

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --anonymous-auth=false    # Add this flag
```

**Insecure kubelet port (10255):**
The read-only port exposes pod and node information without authentication.

```yaml
# /var/lib/kubelet/config.yaml
readOnlyPort: 0    # Disable entirely
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook    # Enforce authorization
```

**Insecure file permissions:**

```bash
# Secure control plane manifests
chmod 600 /etc/kubernetes/manifests/*.yaml

# Secure private keys
chmod 600 /etc/kubernetes/pki/*.key

# Secure etcd data directory
chmod 700 /var/lib/etcd

# After changes, restart kubelet
systemctl daemon-reload && systemctl restart kubelet
```

> **Exam pattern:** Questions often present a kube-bench output showing failures and ask you to remediate specific issues. Practice mapping failure messages to configuration changes.

## TLS for Ingress: Securing External Traffic

Ingress resources manage external access to cluster services, typically HTTP/HTTPS traffic. Without TLS, sensitive data traverses the network in cleartext, vulnerable to interception. Properly configured TLS ensures encrypted communication between clients and your services.

**The TLS configuration workflow:**
1.  Generate or obtain certificates
2.  Create a Kubernetes TLS secret
3.  Reference the secret in your Ingress resource
4.  Verify encrypted connectivity

### Creating a self-signed certificate (exam scenario):

```bash
# Generate private key and certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tls.key \
  -out tls.crt \
  -subj "/CN=[secure-app.example.com/O=MyOrg](https://secure-app.example.com/O=MyOrg)"

# Create the TLS secret
kubectl create secret tls secure-app-tls \
  --key tls.key \
  --cert tls.crt \
  -n <namespace>

# Verify secret creation
kubectl get secret secure-app-tls -n <namespace> -o yaml
```

### Ingress with TLS configuration:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"      # Force HTTPS
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - secure-app.example.com    # Must match certificate CN
    secretName: secure-app-tls  # References our TLS secret
  rules:
  - host: secure-app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: secure-app-service
            port:
              number: 80
```

### Verification:

```bash
# Check ingress configuration
kubectl describe ingress secure-ingress -n production

# Test HTTPS connectivity (allow self-signed with -k)
curl -vk [https://secure-app.example.com](https://secure-app.example.com)

# Verify certificate details
openssl s_client -connect secure-app.example.com:443 -servername secure-app.example.com
```

## Protecting Node Metadata Endpoints

Cloud providers expose instance metadata services at the link-local address `169.254.169.254`. This metadata often includes sensitive information: IAM credentials, instance identity documents, user data scripts, and more. A pod with network access to this endpoint can potentially assume node-level cloud permissions, a critical privilege escalation vector.

**The attack scenario:** An attacker compromises a web application pod. From within that pod, they query the metadata service, retrieve temporary cloud credentials, and use those credentials to access cloud resources (S3 buckets, databases, other services) that the Kubernetes node is authorized to access.

### Network policy to block metadata access:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-cloud-metadata
  namespace: default
spec:
  podSelector: {}    # Apply to all pods
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32    # Block metadata endpoint
```

This policy allows egress to all destinations except the metadata IP. Apply this to every namespace containing application workloads.

### Verification:

```bash
# From within a pod, attempt metadata access
kubectl exec -it <pod-name> -- curl --max-time 2 [http://169.254.169.254/latest/meta-data/](http://169.254.169.254/latest/meta-data/)
# Expected: Connection timeout (not "Connection refused")
```

## Binary Verification Before Deployment

Supply chain attacks targeting Kubernetes binaries represent a sophisticated threat. If an attacker compromises the distribution mechanism, they could inject malicious code into kubectl, kubelet, or other components. Verifying binary checksums ensures you're running authentic, unmodified software.

### Verification workflow:

```bash
# Download the binary and its checksum
VERSION=$(curl -Ls [https://dl.k8s.io/release/stable.txt](https://dl.k8s.io/release/stable.txt))
curl -LO "[https://dl.k8s.io/release/$](https://dl.k8s.io/release/$){VERSION}/bin/linux/amd64/kubectl"
curl -LO "[https://dl.k8s.io/release/$](https://dl.k8s.io/release/$){VERSION}/bin/linux/amd64/kubectl.sha256"

# Verify checksum
echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check
# Expected output: kubectl: OK

# If verification fails, DO NOT use the binary
# Investigate the source and re-download from official channels
```

### Verifying installed binaries:

```bash
# Get running kubelet version
kubelet --version

# Download expected checksum for that version
curl -LO "[https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubelet.sha256](https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubelet.sha256)"

# Compare against installed binary
sha256sum /usr/bin/kubelet
cat kubelet.sha256
# Manual comparison required
```

## Domain 2: Cluster Hardening (15%)

Cluster Hardening focuses on minimizing the blast radius when things go wrong. Even with perfect perimeter security, breaches occur. Hardening ensures that compromised components cannot easily escalate privileges or access resources beyond their intended scope. This domain covers RBAC, service account security, API access restrictions, and upgrade procedures.

### RBAC: The Cornerstone of Kubernetes Authorization

Role-Based Access Control (RBAC) determines who can do what within your cluster. Properly configured RBAC implements the principle of least privilege - users and service accounts receive only the permissions necessary for their legitimate functions. Misconfigured RBAC is among the most common Kubernetes security failures, often granting excessive permissions that attackers exploit.

### Understanding RBAC objects:

| Object | Scope | Purpose |
| :--- | :--- | :--- |
| **Role** | Namespace | Defines permissions within a single namespace |
| **ClusterRole** | Cluster-wide | Defines permissions across all namespaces or for cluster-scoped resources |
| **RoleBinding** | Namespace | Grants a Role's permissions to subjects within that namespace |
| **ClusterRoleBinding** | Cluster-wide | Grants a ClusterRole's permissions cluster-wide to subjects |

**The relationship between these objects:**
Roles/ClusterRoles define what actions are permitted on which resources. Bindings connect these permissions to who (users, groups, or service accounts). A RoleBinding can reference either a Role (same namespace) or a ClusterRole (permissions limited to the binding's namespace). A ClusterRoleBinding always grants cluster-wide permissions.

### Creating a restrictive Role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: development
  name: pod-reader
rules:
- apiGroups: [""]           # Core API group (pods, services, etc.)
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
- apiGroups: [""]
  resources: ["pods/log"]    # Subresource for reading logs
  verbs: ["get"]
```

### Binding the Role to a user:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods-binding
  namespace: development
subjects:
- kind: User
  name: alice
  apiGroup: rbac.authorization.k8s.io
- kind: ServiceAccount
  name: monitoring-sa
  namespace: development
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### Essential RBAC verification commands:

```bash
# Check what YOU can do
kubectl auth can-i create deployments
kubectl auth can-i delete pods --namespace production

# Check what ANOTHER USER can do
kubectl auth can-i list secrets --as alice -n development

# Check what a SERVICE ACCOUNT can do
kubectl auth can-i create pods --as system:serviceaccount:default:my-sa

# List all permissions for a subject
kubectl auth can-i --list --as alice -n development

# Find all RBAC objects
kubectl get roles,rolebindings,clusterroles,clusterrolebindings -A

# Detailed role inspection
kubectl describe role pod-reader -n development
kubectl describe clusterrole admin
```

### Dangerous RBAC patterns to identify and fix:

**Wildcards in roles:**
```yaml
# DANGEROUS - grants all permissions
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

**Secrets access without justification:**
```yaml
# RISKY - secrets often contain credentials
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
```

**Binding to system:authenticated or system:unauthenticated:**
```yaml
# DANGEROUS - grants permissions to all authenticated users
subjects:
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
```

> **Exam tip:** Questions often present an overly permissive role and ask you to reduce its permissions. Practice identifying unnecessary verbs, resources, and API groups.

## Service Account Security

Every pod runs with a service account identity, which Kubernetes uses for authentication and authorization. By default, pods receive the default service account in their namespace, and this account's token is automatically mounted into the pod filesystem. These defaults create unnecessary attack surface—if an attacker compromises a pod, they gain the service account's permissions.

**The service account attack chain:**
1.  Attacker compromises application code (injection, RCE, etc.)
2.  Attacker accesses service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`
3.  Attacker uses token to authenticate to Kubernetes API
4.  Attacker performs actions allowed by the service account's RBAC permissions

### Mitigation 1: Disable automatic token mounting

For the default service account (affects all pods not specifying a service account):

```bash
kubectl patch serviceaccount default -n <namespace> \
  -p '{"automountServiceAccountToken": false}'
```

At the pod level (more granular control):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  serviceAccountName: custom-sa    # Use dedicated SA, not default
  automountServiceAccountToken: false    # Don't mount token
  containers:
  - name: app
    image: nginx:alpine
```

### Mitigation 2: Use dedicated service accounts with minimal permissions

```yaml
# Create a dedicated service account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-specific-sa
  namespace: production
automountServiceAccountToken: false    # SA-level control
---
# Grant only required permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config"]    # Specific resource, not all configmaps
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-specific-sa
  namespace: production
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
```

### Audit service account permissions:

```bash
# List all service accounts
kubectl get serviceaccounts -A

# Check permissions of a specific service account
kubectl auth can-i --list --as=system:serviceaccount:production:app-specific-sa

# Find service accounts with cluster-admin
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]?'
```

## API Server Access Restrictions

The Kubernetes API server is the cluster's central control point, every action flows through it. Securing API server access prevents unauthorized control plane manipulation. This involves authentication configuration, authorization settings, and admission control.

### Disable anonymous authentication:

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --anonymous-auth=false    # Require authentication for all requests
```

### Configure API server audit logging:

Audit logs record all API requests, providing crucial forensic data for security investigations.

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log all requests to secrets at maximum detail
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets"]

# Log pod exec commands
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods/exec", "pods/attach"]

# Log metadata for general pod operations
- level: Metadata
  resources:
  - group: ""
    resources: ["pods"]

# Skip logging health checks
- level: None
  nonResourceURLs:
  - "/healthz*"
  - "/livez*"
  - "/readyz*"
```

### Enable audit logging in API server:

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
    - --audit-log-path=/var/log/kubernetes/audit/audit.log
    - --audit-log-maxage=30        # Days to retain logs
    - --audit-log-maxbackup=10     # Number of backup files
    - --audit-log-maxsize=100      # MB before rotation
  volumeMounts:
  - name: audit-policy
    mountPath: /etc/kubernetes/audit-policy.yaml
    readOnly: true
  - name: audit-logs
    mountPath: /var/log/kubernetes/audit/
volumes:
- name: audit-policy
  hostPath:
    path: /etc/kubernetes/audit-policy.yaml
    type: File
- name: audit-logs
  hostPath:
    path: /var/log/kubernetes/audit/
    type: DirectoryOrCreate
```

## Kubernetes Upgrade Procedures

Running outdated Kubernetes versions exposes clusters to known vulnerabilities with published exploits. Regular upgrades are a security imperative, not just an operational best practice. The CKS tests your ability to perform controlled upgrades following version skew policies.

**Version skew policy:** Components must not be more than one minor version apart. The upgrade order ensures compatibility:
1.  kube-apiserver (control plane API)
2.  kube-controller-manager (controllers)
3.  kube-scheduler (scheduling)
4.  kubelet (node agent)
5.  kube-proxy (network proxy)

### Control plane upgrade with kubeadm:

```bash
# 1. Check current version
kubectl get nodes
kubeadm version

# 2. Find available versions
apt update
apt-cache madison kubeadm | head -20

# 3. Upgrade kubeadm
apt-get update && apt-get install -y kubeadm=1.29.0-*

# 4. Verify upgrade plan
kubeadm upgrade plan

# 5. Apply upgrade (first control plane node)
kubeadm upgrade apply v1.29.0

# 6. Upgrade kubelet and kubectl
apt-get install -y kubelet=1.29.0-* kubectl=1.29.0-*

# 7. Restart kubelet
systemctl daemon-reload
systemctl restart kubelet
```

### Worker node upgrade:

```bash
# On control plane: drain the worker
kubectl drain <worker-node> --ignore-daemonsets --delete-emptydir-data

# On worker node: upgrade kubeadm
apt-get update && apt-get install -y kubeadm=1.29.0-*

# Upgrade node configuration
kubeadm upgrade node

# Upgrade kubelet
apt-get install -y kubelet=1.29.0-*
systemctl daemon-reload
systemctl restart kubelet

# On control plane: uncordon the worker
kubectl uncordon <worker-node>
```

## Domain 3: System Hardening (10%)

System Hardening addresses the operating system layer beneath Kubernetes. A compromised node OS can undermine all cluster-level security controls. This domain covers host footprint minimization, access management, network restrictions, and kernel hardening with AppArmor and seccomp.

### Minimizing Host OS Footprint

Every installed package, running service, and open port represents potential attack surface. A minimal host OS includes only components necessary for running Kubernetes workloads, nothing more.

### Service audit and reduction:

```bash
# List all running services
systemctl list-units --type=service --state=running

# Identify services to disable (examples)
systemctl stop cups           # Printing - unnecessary on cluster nodes
systemctl disable cups
systemctl mask cups           # Prevent any start attempt

# View listening ports
ss -tulnp                     # TCP/UDP listeners with process names
netstat -tulnp                # Alternative command
lsof -i -P -n | grep LISTEN   # Another alternative
```

**Services typically unnecessary on Kubernetes nodes:**
* Print services (`cups`)
* GUI/display managers
* FTP servers
* Mail servers (unless specifically required)
* Development tools (compilers, debuggers)

### Package audit:

```bash
# List installed packages (Debian/Ubuntu)
dpkg -l | grep -E '^ii'

# Remove unnecessary packages
apt-get remove --purge <package-name>
apt-get autoremove
```

## AppArmor: Application-Level Security Profiles

AppArmor is a Linux Security Module that restricts program capabilities through security profiles. In Kubernetes, AppArmor profiles confine containers to specific allowed behaviors, preventing exploitation even if application code is compromised.

**AppArmor fundamentals:**
AppArmor profiles define what files a program can access, what capabilities it can use, and what network operations it can perform. Profiles operate in two modes:
* **Enforce:** Violations are blocked and logged
* **Complain:** Violations are logged but allowed (useful for developing profiles)

### Verify AppArmor is enabled:

```bash
# Check kernel module
cat /sys/module/apparmor/parameters/enabled    # Should return: Y

# View loaded profiles
aa-status
# Output shows:
# - Number of profiles loaded
# - Profiles in enforce mode
# - Profiles in complain mode
```

**Profile locations:** `/etc/apparmor.d/`

### Loading and managing profiles:

```bash
# Load a new profile
apparmor_parser -q /etc/apparmor.d/my-custom-profile

# Reload an existing profile
apparmor_parser -r /etc/apparmor.d/my-custom-profile

# Set profile to complain mode (for testing)
aa-complain /etc/apparmor.d/my-custom-profile

# Set profile to enforce mode
aa-enforce /etc/apparmor.d/my-custom-profile
```

### Applying AppArmor profiles to pods (Kubernetes v1.30+):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: apparmor-demo
spec:
  securityContext:
    appArmorProfile:
      type: Localhost
      localhostProfile: k8s-custom-nginx-deny-write
  containers:
  - name: nginx
    image: nginx:alpine
```

### Legacy annotation method (pre-v1.30):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: apparmor-demo
  annotations:
    container.apparmor.security.beta.kubernetes.io/nginx: localhost/k8s-custom-nginx-deny-write
spec:
  containers:
  - name: nginx
    image: nginx:alpine
```

### Example profile denying writes except to /tmp:

```bash
#include <tunables/global>

profile k8s-custom-nginx-deny-write flags=(attach_disconnected) {
  #include <abstractions/base>
  
  # Allow read access everywhere
  file,
  
  # Deny all writes except to /tmp
  deny /** w,
  /tmp/** rw,
  
  # Allow network access
  network,
}
```

## Seccomp: System Call Filtering

Seccomp (Secure Computing Mode) filters system calls available to containers. By restricting the syscall interface, seccomp limits what kernel functionality attackers can abuse, even after gaining code execution.

**Why seccomp matters:** Container escapes often exploit kernel vulnerabilities through specific system calls. By blocking unnecessary syscalls, seccomp reduces the attack surface dramatically. The `RuntimeDefault` profile blocks dozens of dangerous syscalls while allowing normal container operation.

**Profile storage location:** `/var/lib/kubelet/seccomp/`

### Applying RuntimeDefault seccomp (recommended baseline):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-demo
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault    # Use container runtime's default profile
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      allowPrivilegeEscalation: false
```

### Custom localhost profile:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: custom-seccomp
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/custom-audit.json    # Relative to /var/lib/kubelet/seccomp/
  containers:
  - name: app
    image: nginx:alpine
```

### Example audit profile (/var/lib/kubelet/seccomp/profiles/custom-audit.json):

```json
{
  "defaultAction": "SCMP_ACT_LOG",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["ptrace", "personality"],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
```

This profile logs all syscalls (useful for developing stricter profiles) while explicitly blocking `ptrace` and `personality` (commonly abused syscalls).

## Domain 4: Minimize Microservice Vulnerabilities (20%)

This high-weight domain focuses on securing individual workloads through Pod Security Standards, secrets management, isolation techniques, and encrypted pod-to-pod communication. These controls operate at the application layer, protecting against both external attacks and compromised workloads.

### Pod Security Standards: Built-in Admission Control

Pod Security Standards (PSS) define three progressively restrictive security profiles that clusters enforce through Pod Security Admission (PSA). This built-in mechanism replaced the deprecated PodSecurityPolicy, providing a simpler, more maintainable approach to pod security enforcement.

**The three security profiles:**

| Profile | Purpose | Use Case |
| :--- | :--- | :--- |
| **Privileged** | Unrestricted, no security requirements | System components, infrastructure pods |
| **Baseline** | Prevents known privilege escalations | General workloads with minimal restrictions |
| **Restricted** | Heavily hardened, security best practices | Sensitive workloads, multi-tenant environments |

**What Baseline prevents:**
* HostNetwork, HostPID, HostIPC
* Privileged containers
* Adding capabilities beyond limited set
* HostPath volumes (except for specific safe paths)

**What Restricted additionally requires:**
* Running as non-root
* Seccomp profile (RuntimeDefault or Localhost)
* Dropping ALL capabilities
* Read-only root filesystem (recommended, not required)
* No privilege escalation

**Enforcement modes:**

| Mode | Behavior |
| :--- | :--- |
| **enforce** | Violations reject pod creation |
| **audit** | Violations logged, pods created |
| **warn** | Violations generate user-facing warnings |

### Applying PSA through namespace labels:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # Enforce restricted profile - violations are rejected
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    # Audit against restricted - violations are logged
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
    # Warn against restricted - users see warnings
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
```

### Quick kubectl method:

```bash
kubectl label --overwrite ns production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
```

### Pod that meets Restricted requirements:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: compliant-pod
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: var-cache-nginx
      mountPath: /var/cache/nginx
    - name: var-run
      mountPath: /var/run
  volumes:
  - name: tmp
    emptyDir: {}
  - name: var-cache-nginx
    emptyDir: {}
  - name: var-run
    emptyDir: {}
```

## Kubernetes Secrets Management

Secrets store sensitive data passwords, tokens, keys separately from pod specifications. While Kubernetes Secrets are not encrypted by default (only base64-encoded), proper configuration enables encryption at rest, protecting data in etcd.

### Creating secrets:

```bash
# From literal values
kubectl create secret generic db-credentials \
  --from-literal=username=admin \
  --from-literal=password=supersecret123 \
  -n production

# From files
kubectl create secret generic tls-certs \
  --from-file=cert.pem \
  --from-file=key.pem \
  -n production

# View secret (base64 encoded)
kubectl get secret db-credentials -n production -o yaml

# Decode a value
kubectl get secret db-credentials -n production -o jsonpath='{.data.password}' | base64 -d
```

### Encryption at rest configuration:

By default, secrets are stored as plaintext in etcd. Encryption at rest protects against etcd backup exposure and unauthorized etcd access.

**Generate encryption key:**
```bash
head -c 32 /dev/urandom | base64
# Output: <32-byte-random-base64-encoded-key>
```

**Create encryption configuration:**
```yaml
# /etc/kubernetes/enc/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <your-32-byte-base64-key>
      - identity: {}    # Fallback to read existing unencrypted secrets
```

**Enable encryption in API server:**
```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --encryption-provider-config=/etc/kubernetes/enc/encryption-config.yaml
  volumeMounts:
  - name: encryption-config
    mountPath: /etc/kubernetes/enc
    readOnly: true
volumes:
- name: encryption-config
  hostPath:
    path: /etc/kubernetes/enc
    type: DirectoryOrCreate
```

**Verify encryption is working:**
```bash
# Create a test secret
kubectl create secret generic test-encryption --from-literal=mykey=mydata

# Read directly from etcd
ETCDCTL_API=3 etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/test-encryption | hexdump -C

# Should show "k8s:enc:aescbc:v1:key1" prefix indicating encryption
# If you see plaintext "mydata", encryption is not working
```

**Re-encrypt existing secrets:**
```bash
kubectl get secrets -A -o json | kubectl replace -f -
```

## Isolation Techniques: Sandboxed Containers

Standard containers share the host kernel, meaning kernel vulnerabilities can lead to container escapes. Sandboxed runtimes like gVisor and Kata Containers provide additional isolation layers, protecting the host from malicious or buggy container workloads.

**gVisor architecture:** gVisor implements a user-space kernel that intercepts container system calls. The container "thinks" it's talking to a Linux kernel, but gVisor handles syscalls in user space, limiting exposure to the actual host kernel.

### RuntimeClass configuration for gVisor:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc    # Corresponds to containerd runtime handler
scheduling:
  nodeSelector:
    sandbox-enabled: "true"    # Only schedule on nodes with gVisor
```

### Using RuntimeClass in a pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sandboxed-workload
spec:
  runtimeClassName: gvisor
  containers:
  - name: untrusted-code
    image: nginx:alpine
```

### Verify sandbox is active:

```bash
kubectl exec sandboxed-workload -- dmesg | head
# Should show: "Starting gVisor..." instead of normal Linux kernel messages
```

**Trade-offs:** Sandboxed runtimes introduce performance overhead and may not support all applications (especially those making heavy use of syscalls or requiring specific kernel features). Use them for untrusted workloads where isolation is paramount.

## Pod-to-Pod Encryption with Service Mesh

By default, pod-to-pod communication is unencrypted. While network policies control which pods can communicate, they don't protect the content of that communication. Service meshes like Istio and Cilium provide mutual TLS (mTLS), encrypting all service-to-service traffic.

### Istio strict mTLS configuration:

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system    # Mesh-wide policy
spec:
  mtls:
    mode: STRICT    # Require mTLS for all communication
```

### Namespace-specific mTLS:

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: require-mtls
  namespace: production
spec:
  mtls:
    mode: STRICT
```

### Verify mTLS is active:

```bash
# Check if sidecar is injected
kubectl get pods -n production -o jsonpath='{.items[*].spec.containers[*].name}' | tr ' ' '\n' | grep istio

# Verify mTLS status
istioctl authn tls-check <pod-name>.<namespace>
```

## Domain 5: Supply Chain Security (20%)

Supply chain security addresses the provenance and integrity of software artifacts, container images, dependencies, configuration files before they enter your cluster. This domain covers image minimization, SBOM understanding, registry security, artifact signing, and static analysis.

### Minimizing Base Image Footprint

Every package in a container image represents potential vulnerabilities. Minimal images reduce attack surface, speed deployment, and simplify security scanning.

**Image hierarchy by attack surface (smallest to largest):**
1.  **Scratch** - Empty image, only your binary
2.  **Distroless** - Minimal runtime without package manager or shell
3.  **Alpine** - Minimal Linux with musl libc and ash shell
4.  **Debian/Ubuntu slim** - Stripped-down traditional distributions
5.  **Full distributions** - Complete OS with all tools (avoid for production)

### Multi-stage build for minimal images:

```dockerfile
# Build stage - full toolchain
FROM golang:1.21 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /myapp

# Production stage - minimal runtime
FROM gcr.io/distroless/static-debian12
COPY --from=build /myapp /
USER nonroot:nonroot    # Run as non-root user
ENTRYPOINT ["/myapp"]
```

### Analyzing image layers:

```bash
# View layer history
docker history --no-trunc nginx:latest

# Detailed layer analysis with dive
dive nginx:latest
```

## Trivy: Comprehensive Vulnerability Scanning

Trivy is an all-in-one security scanner supporting container images, filesystems, Git repositories, and Kubernetes clusters. It's the primary scanning tool available during the CKS exam.

### Essential Trivy commands:

```bash
# Scan an image
trivy image nginx:latest

# Show only HIGH and CRITICAL vulnerabilities
trivy image --severity HIGH,CRITICAL nginx:latest

# Ignore unfixed vulnerabilities (only show fixable issues)
trivy image --ignore-unfixed nginx:latest

# Scan a local tarball
trivy image --input myimage.tar

# Scan Kubernetes manifests for misconfigurations
trivy config /path/to/manifests/

# Scan a running cluster
trivy k8s --report summary cluster

# Output as JSON for processing
trivy image -f json -o results.json nginx:latest
```

**Understanding Trivy output:**
Trivy reports include:
* CVE ID - Unique vulnerability identifier
* Severity - CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
* Package - Affected component
* Installed Version - Current vulnerable version
* Fixed Version - Version with fix (if available)

> **Exam tip:** Questions may ask you to scan images and identify vulnerable pods, or to update images to versions without critical vulnerabilities.

## Kubesec: Security Risk Analysis for Manifests

Kubesec statically analyzes Kubernetes resource definitions, scoring them based on security best practices.

```bash
# Scan a manifest file
kubesec scan pod.yaml

# Scan from stdin
kubectl get pod mypod -o yaml | kubesec scan -

# Use the online API
curl -sSX POST --data-binary @pod.yaml [https://v2.kubesec.io/scan](https://v2.kubesec.io/scan)
```

### Scoring factors - example:

| Configuration | Points |
| :--- | :--- |
| `readOnlyRootFilesystem: true` | +1 |
| `runAsNonRoot: true` | +1 |
| `runAsUser > 10000` | +1 |
| `capabilities.drop: ["ALL"]` | +1 |
| `serviceAccountName != default` | +1 |
| `privileged: true` | -30 (critical) |
| `hostNetwork: true` | -9 |
| `hostPID: true` | -9 |

## KubeLinter: Best Practice Enforcement

KubeLinter checks Kubernetes YAML files against a set of best practices.

```bash
# Scan a single file
kube-linter lint pod.yaml

# Scan a directory
kube-linter lint ./manifests/

# List available checks
kube-linter checks list

# Run specific checks only
kube-linter lint --include "run-as-non-root,no-read-only-root-fs" pod.yaml
```

## OPA Gatekeeper: Policy as Code

Gatekeeper enables custom admission control policies using Rego, the Open Policy Agent language. Common use cases include restricting image registries, requiring labels, and enforcing resource limits.

### Registry restriction with Gatekeeper:

```yaml
# ConstraintTemplate - defines the policy logic
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedregistries
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRegistries
      validation:
        openAPIV3Schema:
          type: object
          properties:
            registries:
              type: array
              items:
                type: string
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sallowedregistries

      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        not registry_allowed(container.image)
        msg := sprintf("Container image '%v' is from an untrusted registry", [container.image])
      }

      violation[{"msg": msg}] {
        container := input.review.object.spec.initContainers[_]
        not registry_allowed(container.image)
        msg := sprintf("Init container image '%v' is from an untrusted registry", [container.image])
      }

      registry_allowed(image) {
        registry := input.parameters.registries[_]
        startswith(image, registry)
      }
---
# Constraint - applies the policy with parameters
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRegistries
metadata:
  name: require-trusted-registries
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
  parameters:
    registries:
    - "gcr.io/my-company/"
    - "docker.io/library/"
    - "[registry.internal.example.com/](https://registry.internal.example.com/)"
```

### Verification:

```bash
# List constraint templates
kubectl get constrainttemplates

# List constraints
kubectl get constraints

# Test policy (should be rejected)
kubectl run test --image=[untrusted-registry.com/malicious:latest](https://untrusted-registry.com/malicious:latest)
```

## Domain 6: Monitoring, Logging, and Runtime Security (20%)

This final domain covers detecting and responding to security incidents. While other domains focus on prevention, runtime security assumes breaches occur and emphasizes detection, investigation, and response.

### Falco: Runtime Threat Detection

Falco is a cloud-native runtime security tool that uses kernel instrumentation to detect anomalous behavior. Unlike static scanning, Falco observes actual runtime behavior—file access, network connections, process execution—and alerts on suspicious patterns.

**How Falco works:**
1.  Falco loads into the kernel (via module or eBPF)
2.  Monitors system calls in real-time
3.  Evaluates syscalls against rule conditions
4.  Generates alerts for matches

**Configuration locations:**

| File | Purpose |
| :--- | :--- |
| `/etc/falco/falco.yaml` | Main configuration |
| `/etc/falco/falco_rules.yaml` | Default rules (don't edit) |
| `/etc/falco/falco_rules.local.yaml` | Custom rules (edit this) |

### Essential Falco commands:

```bash
# Check service status
systemctl status falco

# View real-time logs
journalctl -fu falco

# Run Falco manually with custom rules
falco -r /path/to/custom_rules.yaml

# Run for 60 seconds and save output
falco -M 60 | tee falco_output.txt

# List available fields for rule writing
falco --list
```

### Understanding Falco rules:

```yaml
- rule: Shell Spawned in Container
  desc: Detect shell execution inside a container
  condition: >
    spawned_process and 
    container and 
    shell_procs
  output: >
    Shell spawned in container 
    (user=%user.name container_id=%container.id 
    container_name=%container.name shell=%proc.name 
    parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

**Rule components:**
* **condition:** Boolean expression using Falco fields
* **output:** Alert message with field substitutions
* **priority:** EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG
* **tags:** Categorization for filtering

**Common Falco macros (predefined conditions):**
```yaml
# These are built into Falco - reference them in rules
container                 # Event occurred inside a container
spawned_process           # A new process was created
shell_procs               # Process is a shell (bash, sh, etc.)
sensitive_files           # Access to /etc/shadow, /etc/passwd, etc.
package_mgmt_procs        # Package managers (apt, yum, etc.)
```

### Custom rule example - detect crypto mining:

```yaml
- rule: Cryptocurrency Mining Activity
  desc: Detect potential crypto mining based on process names
  condition: >
    spawned_process and 
    container and
    (proc.name in (xmrig, minerd, minergate) or
     proc.cmdline contains "stratum+tcp")
  output: >
    Cryptocurrency mining detected 
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [cryptomining, mitre_resource_hijacking]
```

## Container Immutability at Runtime

Immutable containers cannot be modified after startup. This prevents attackers from installing tools, modifying configurations, or establishing persistence—even after gaining code execution.

### Comprehensive immutable pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: immutable-workload
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: gcr.io/distroless/static:nonroot
    securityContext:
      readOnlyRootFilesystem: true    # Critical for immutability
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /var/cache
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
```

### Testing immutability:

```bash
# Attempt to write to root filesystem
kubectl exec immutable-workload -- touch /test
# Expected: "Read-only file system" error

# Verify writable volumes work
kubectl exec immutable-workload -- touch /tmp/test
# Should succeed
```

## Kubernetes Audit Logs

Audit logs record all requests to the Kubernetes API server, providing a forensic trail for security investigations. Understanding audit logs helps identify unauthorized access, track changes, and detect suspicious patterns.

**Audit levels (increasing detail):**

| Level | Records |
| :--- | :--- |
| **None** | Nothing |
| **Metadata** | Request metadata (user, timestamp, resource, verb) |
| **Request** | Metadata + request body |
| **RequestResponse** | Metadata + request body + response body |

### Comprehensive audit policy:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log all access to secrets with full request/response
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets"]
  
# Log exec/attach commands
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods/exec", "pods/attach", "pods/portforward"]

# Log RBAC changes
- level: RequestResponse
  resources:
  - group: "rbac.authorization.k8s.io"
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]

# Log configmap changes
- level: Request
  resources:
  - group: ""
    resources: ["configmaps"]
  
# Metadata for general pod operations
- level: Metadata
  resources:
  - group: ""
    resources: ["pods"]

# Skip noisy endpoints
- level: None
  resources:
  - group: ""
    resources: ["events"]
- level: None
  users: ["system:kube-proxy"]
- level: None
  nonResourceURLs:
  - "/healthz*"
  - "/livez*"
  - "/readyz*"
  - "/metrics"
```

### Analyzing audit logs:

```bash
# Find pod deletions
cat /var/log/kubernetes/audit/audit.log | jq 'select(.verb=="delete" and .objectRef.resource=="pods")'

# Find secret access
cat /var/log/kubernetes/audit/audit.log | jq 'select(.objectRef.resource=="secrets")'

# Find anonymous access attempts
cat /var/log/kubernetes/audit/audit.log | jq 'select(.user.username=="system:anonymous")'

# Find failed authentication
cat /var/log/kubernetes/audit/audit.log | jq 'select(.responseStatus.code >= 400)'

# Find exec commands
cat /var/log/kubernetes/audit/audit.log | jq 'select(.objectRef.subresource=="exec")'
```

## crictl: Container Runtime Investigation

`crictl` is a CLI tool for CRI-compatible container runtimes (containerd, CRI-O). It's essential for investigating container-level issues when `kubectl` provides insufficient detail.

### Configuration (/etc/crictl.yaml):

```yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 10
debug: false
```

### Essential crictl commands:

```bash
# List pods
crictl pods

# List all containers (including stopped)
crictl ps -a

# Inspect container configuration
crictl inspect <container-id>

# View container logs
crictl logs <container-id>
crictl logs -f <container-id>    # Follow logs

# Execute command in container
crictl exec -it <container-id> /bin/sh

# Pull an image
crictl pull nginx:latest

# List images
crictl images

# Remove container
crictl rm <container-id>

# Pod-level operations
crictl stopp <pod-id>
crictl rmp <pod-id>
```

### Investigation workflow example:

```bash
# 1. Identify suspicious pod
crictl pods | grep -i suspicious

# 2. Get containers in pod
crictl ps --pod <pod-id>

# 3. Check container details
crictl inspect <container-id> | jq '.info.config.process'

# 4. Review recent logs
crictl logs --tail 100 <container-id>

# 5. Check running processes (if shell available)
crictl exec <container-id> ps aux
```

## Quick Reference: Critical File Paths

| Purpose | Path |
| :--- | :--- |
| API Server manifest | `/etc/kubernetes/manifests/kube-apiserver.yaml` |
| Controller Manager manifest | `/etc/kubernetes/manifests/kube-controller-manager.yaml` |
| Scheduler manifest | `/etc/kubernetes/manifests/kube-scheduler.yaml` |
| etcd manifest | `/etc/kubernetes/manifests/etcd.yaml` |
| Kubelet configuration | `/var/lib/kubelet/config.yaml` |
| PKI certificates | `/etc/kubernetes/pki/` |
| etcd data directory | `/var/lib/etcd/` |
| Audit policy | `/etc/kubernetes/audit-policy.yaml` |
| Audit logs | `/var/log/kubernetes/audit/audit.log` |
| AppArmor profiles | `/etc/apparmor.d/` |
| Seccomp profiles | `/var/lib/kubelet/seccomp/` |
| Falco configuration | `/etc/falco/falco.yaml` |
| Falco default rules | `/etc/falco/falco_rules.yaml` |
| Falco custom rules | `/etc/falco/falco_rules.local.yaml` |
| Container logs | `/var/log/containers/` |
| crictl configuration | `/etc/crictl.yaml` |
| Encryption configuration | `/etc/kubernetes/enc/encryption-config.yaml` |

## Final Verification Checklist

**Cluster Setup**
* [ ] NetworkPolicies exist in critical namespaces: `kubectl get netpol -A`
* [ ] Default deny policies applied where needed
* [ ] kube-bench shows no FAIL results: `kube-bench run`
* [ ] Ingress resources have TLS configured: `kubectl get ingress -A -o wide`
* [ ] Cloud metadata access blocked from pods
* [ ] Binary checksums verified

**Cluster Hardening**
* [ ] RBAC follows least privilege: `kubectl auth can-i --list`
* [ ] Default service accounts patched: `automountServiceAccountToken: false`
* [ ] No wildcards in production roles
* [ ] Anonymous authentication disabled: Check apiserver flags
* [ ] Audit logging enabled: Check `/var/log/kubernetes/audit/`

**System Hardening**
* [ ] Unnecessary services disabled: `systemctl list-units --type=service`
* [ ] AppArmor profiles loaded: `aa-status`
* [ ] seccomp RuntimeDefault applied to workloads

**Microservice Security**
* [ ] PSA labels on namespaces: `kubectl get ns --show-labels`
* [ ] Secrets encrypted at rest: Verify with `etcdctl`
* [ ] RuntimeClass configured for sensitive workloads
* [ ] Pods run as non-root where possible

**Supply Chain Security**
* [ ] Images scanned before deployment: `trivy image`
* [ ] Only trusted registries permitted: Check Gatekeeper constraints
* [ ] Manifests pass KubeLinter/Kubesec checks
* [ ] Multi-stage builds use minimal base images

**Runtime Security**
* [ ] Falco running and configured: `systemctl status falco`
* [ ] Containers use `readOnlyRootFilesystem`
* [ ] Audit policy captures security events
* [ ] Investigation tools available: `crictl`, `jq`
