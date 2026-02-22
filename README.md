# CKS Mock Exam Preparation Lab ☸️

This repository contains a collection of practical, hands-on scenarios designed to help you prepare for the **Certified Kubernetes Security Specialist (CKS)** exam. 

These exercises are built for a self-hosted `kubeadm` cluster (e.g., running on Proxmox with Istio/Cilium) and cover the core domains of the CKS curriculum, from cluster setup and hardening to runtime security.

This entire repository consists of summarys from Killerkoda/KodeKloud and a lot of mockexam questions. Best of luck! :) 

## Table of Contents
1. [Admission Controllers (ImagePolicyWebhook & NodeRestriction)](#1-admission-controllers)
2. [Kubeadm Node Upgrade](#2-kubeadm-node-upgrade)
3. [Runtime Security with Falco](#3-runtime-security-with-falco)
4. [Dockerfile & Deployment Security](#4-dockerfile--deployment-security)
5. [AppArmor, Seccomp & Pod Security Standards](#5-apparmor-seccomp--pod-security-standards)
6. [Kube-bench & CIS Benchmarks](#6-kube-bench--cis-benchmarks)
7. [Malicious Processes & Container Removal](#7-malicious-processes--container-removal)
8. [Pod Security: Immutability, Non-Root & Projected Volumes](#8-pod-security-immutability-non-root--projected-volumes)
9. [Validating Kubernetes Binaries](#9-validating-kubernetes-binaries)
10. [etcd Encryption at Rest](#10-etcd-encryption-at-rest)

---

## 1. Admission Controllers
**Task:** Enable `NodeRestriction` and `ImagePolicyWebhook` on the API server.

**Solution:**
1. Create the admission config and webhook kubeconfig files in `/etc/kubernetes/admission/`.
2. Edit `/etc/kubernetes/manifests/kube-apiserver.yaml`:
   ```yaml
   spec:
     containers:
     - command:
       - kube-apiserver
       - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
       - --admission-control-config-file=/etc/kubernetes/admission/admission-config.yaml
       volumeMounts:
       - mountPath: /etc/kubernetes/admission
         name: admission-config
         readOnly: true
     volumes:
     - hostPath:
         path: /etc/kubernetes/admission
         type: DirectoryOrCreate
       name: admission-config

## 2. Kubeadm Node Upgrade
**Task:** Safely drain and upgrade a worker node to the next Kubernetes version.

**Solution:**
# On Master:
kubectl drain <node-name> --ignore-daemonsets --force

# On Worker Node:
apt-mark unhold kubeadm kubelet kubectl
apt-get update && apt-get install -y kubeadm='1.31.*'
kubeadm upgrade node
apt-get install -y kubelet='1.31.*' kubectl='1.31.*'
systemctl daemon-reload && systemctl restart kubelet
apt-mark hold kubeadm kubelet kubectl

# On Master:
kubectl uncordon <node-name>

## 3. Runtime Security with Falco
**Task:** Create a custom rule to alert when /etc/shadow is read.

**Solution:** 

Add the following to /etc/falco/falco_rules.local.yaml:

- rule: Detect Shadow File Read
  desc: Alert when /etc/shadow is read
  condition: open_read and fd.name = "/etc/shadow"
  output: "Warning: /etc/shadow was read (user=%user.name command=%proc.cmdline)"
  priority: WARNING
  tags: [filesystem, mitre_credential_access]

Restart Falco: systemctl restart falco.

journalctl -f falco / systemctl status falco

## 4. Dockerfile & Deployment Security
**Task:** Fix a vulnerable Dockerfile and Deployment (remove root, latest tags, and privileges).

**Solution:**

Secure Dockerfile:

FROM ubuntu:24.04 
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
RUN apt-get update && apt-get install -y curl
COPY app.tar.gz /opt/app/
RUN chown -R appuser:appgroup /opt/app/
USER appuser
CMD ["/opt/app/run.sh"]

Secure Deployment SecurityContext:

securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL

## 5. AppArmor, Seccomp & Pod Security Standards
**Task:** Apply an AppArmor profile, enforce a Restricted PSS, and set Seccomp.

**Solution:**

Load AppArmor on the node: apparmor_parser -q /path/to/secure-profile

Enforce PSS on the namespace:
kubectl label namespace secured-area pod-security.kubernetes.io/enforce=restricted

Secure Pod YAML:
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/nginx: localhost/secure-profile
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault

## 6. Kube-bench & CIS Benchmarks
**Task:** Fix a kube-bench failure related to anonymous auth on the Kubelet.

**Solution:**

Edit /var/lib/kubelet/config.yaml on the target node:

YAML
authentication:
  anonymous:
    enabled: false
Restart Kubelet: systemctl daemon-reload && systemctl restart kubelet.

## 7. Malicious Processes & Container Removal
**Task:** Identify and stop a container running a malicious process (e.g., cryptominer).

**Solution:**

Access the worker node and use crictl:

Bash
crictl ps              # Find the container ID
crictl stop <id>       # Stop it
crictl rm <id>         # Remove it entirely

## 8. Pod Security: Immutability, Non-Root & Projected Volumes
**Task:** Disable automatic SA token mounting, enforce a read-only root filesystem, run as non-root, and mount the token manually via a projected volume.

**Solution:**

ServiceAccount (Disable automount):

apiVersion: v1
kind: ServiceAccount
metadata:
  name: restricted-sa
automountServiceAccountToken: false

Deployment:

apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      serviceAccountName: restricted-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000 
      containers:
      - name: app
        image: busybox:1.36
        command: ["sleep", "3600"]
        securityContext:
          readOnlyRootFilesystem: true
        volumeMounts:
        - name: sa-token-projected
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount/token
          readOnly: true
        - name: tmp-volume
          mountPath: /tmp
      volumes:
      - name: sa-token-projected
        projected:
          defaultMode: 0444
          sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 3600
      - name: tmp-volume
        emptyDir: {}

## 9. Validating Kubernetes Binaries
**Task:** Ensure static pod manifests haven't been tampered with.

**Solution:**

sha512sum /etc/kubernetes/manifests/kube-apiserver.yaml > apiserver.hash
sha512sum -c apiserver.hash  # Will output OK or FAILED

## 10. etcd Encryption at Rest
**Task:** Encrypt Secret resources in etcd using aescbc.

**Solution:**

Create /etc/kubernetes/etcd-encryption.yaml with your base64 AES key.

Edit /etc/kubernetes/manifests/kube-apiserver.yaml:

spec:
  containers:
  - command:
    - kube-apiserver
    - --encryption-provider-config=/etc/kubernetes/etcd-encryption.yaml
    volumeMounts:
    - mountPath: /etc/kubernetes/etcd-encryption.yaml
      name: etcd-encryption
      readOnly: true
  volumes:
  - hostPath:
      path: /etc/kubernetes/etcd-encryption.yaml
      type: FileOrCreate
    name: etcd-encryption

