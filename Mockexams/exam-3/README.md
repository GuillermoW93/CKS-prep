Questions to expect:

* Admission Controller (NodeRestriction/ImagePolicyWebhook)
* Upgrade the node to the same version as the control plane
* Network Policy
* Falco rules
* Cillium Network Policy (CNP)
* Implement Istio to enable mTLS
* Find the issues in the Dockerfile and deployment (correct them)
* Apparmor and Seccomp profiles
* Kube-bench to fix the FAIL tests in CIS benchmarks
* Check the syscalls and remove that container or pod
* SBOM
* Pod Security Standard
* Automount the serviceaccount token to the pod
* Auditing the kube-apiserver
* Container immutability
* Validating the binaries of kubernetes components with sha512sum
* Trivy scan
* Container should run with rootOnlyFileSystem and non-Root

----

Examples:
* "curl https://dl.k8s.io/v1.20.0/kubernetes.tar.gz -L -o kubernetes.tar.gz"
* "shasum -a 512 kubernetes.tar.gz (sha512sum)"

There are 3 deployments (nvdia , cpu, gpu) that uses the same image. And was asking to identify the pod that access the memory location /dev/mem. And scale down the deployment
- Check the pod's securityContext for privileged access or hostPath volumes. Use kubectl describe to examine pods.

Apod with 3 containers. 3 containers are using the same Image but different tags. So I need to get the image that has a specific version of libcrypto version. And create a spdx sbom with a tool called “bom”.
- Examine each container's image to check the version of libcrypto. You can do this by pulling the image locally and inspecting it or by using the docker run command to inspect the installed packages
- bom generate --image alpine:3.19.1 --output alpine.spdx
- k get pods -n <namespace> -o yaml | grep image

for i in <first_image> <second_image> <third_image>; do bom generate --image $i | grep libcrypto; done


Remove a Linux user called “developer” from the "docker" group. And also deny tcp traffic from docker daemon. How to do this?
- udo gpasswd -d developer docker . To deny tcp traffic from docker daemon you would edit the /etc/docker/daemon.json file and remove tcp host entries. Leave unix:///var/run/docker.sock in there as that allows socket communication. Then restart docker daemon and check status. sudo systemctl restart docker

Cillium L4 mutual TLS 


https://docs.cilium.io/en/stable/network/servicemesh/mutual-authentication/mutual-authentication-example/

Basically you have to add below two lines to your CNP,
authentication:
mode: "required"

kubectl apply -f - <<EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: no-mutual-auth-echo-app-routeble-demo
  namespace: app-routable-demo
spec:
  endpointSelector:
    matchLabels:
       app: nginx-zone1
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: siege
    authentication:
      mode: "required"
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      rules:
        http:
        - method: "GET"
          path: "/app1"
EOF

kubectl apply -f - <<EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: no-mutual-auth-echo-app-routeble-demo
  namespace: app-routable-demo
spec:
  endpointSelector:
    matchLabels:
       app: nginx-zone1
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: siege
    authentication:
      mode: "required"
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      rules:
        http:
        - method: "GET"
          path: "/app1"
EOF

Falco rule for /dev/mem
- rule: Detect dev mem access
  desc: A rule to check if fd.name is /dev/mem
  condition: fd.name = /dev/mem
  output: "Sensitive file opened (user=%user.name command=%proc.cmdline file=%fd.name)"
  priority: WARNING

-------


Extra questions: 

Istio apply mtls sidecar https://istio.io/latest/docs/tasks/security/authentication/mtls-migration/#lock-down-to-mutual-tls-by-namespace https://istio.io/latest/docs/setup/additional-setup/sidecar-injection/#deploying-an-app


Ingress with tls: Given a secret tls and create an Ingress tls. Also redirect http request to https (should use ingressClassName: nginx with the annotation ssl-redirect https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/

Docker daemon secure: Require 1: remove user “develop” from group docker Require 2: Then chown root:root of Docker sock /var/run/docker.sock Require 3: Docker daemon change to unix from tcp ( /lib/systemd/system/docker.service)

Bom: There’s a pod alpine with 3 containers using image alpine with different version 3.20.0, 3.19.6 and 3.16.1.
Require 1: Check with container has libcrypto3 version x.y.z and change the deployment yaml file remove that container, then redeploy
Require 2: Generate a SPDX report write to file.

Static file analysic: Given: A long Dockerfile and a deploy yaml file.
Require 1: change one line only and DO NOT add/remove any lines, dont build the image (it mentioned in the question) → Change USER root to USER couchdb.
Require 2: change one line only and DO NOT add/remove any lines → Change readOnlyRootFilesystem from false to true.

Secret TLS: Given: A deployment yaml file, a cert file and a key file Require: Create a tls secret in a namespace → apply it to the deployment yaml file and apply it.

Projected volume and SA: Given: an SA and a deployment yaml file.

Require 1: Change the SA automountServiceAccountToken to false

Require 2: Using projected volume for the deployment under /var/run/secrets/kubernestes.io/serviceaccount/token

- Kube-bench Fix 3 small issues
- Auditing
- ImagePolicyWebhook
- Network policies: create 2 policies (no CiliunmNetworkPolicies)
- PSS: Try to fix the given deployment yaml file to make the pod running. Check replicaset event.
- Kube-apiserver: change the anonymous-auth flag and delete a clusterrolebinding system:anonymous
- Seccomp profile apply
- Upgrade worker node from 1.33.0 to 1.33.1

* adding simple custom falco rule to detect read access to sensitive host file
* enabling audit policy via kube-apiserver and customising the policy.yaml
* enabling AdmissionController and webhooks, how to configure and debug ImagePolicyWebhook entire lifecycle
* how to effectively use bom and trivy to detect the dependencies in an image
* network policy, default deny/ namespaceSelection/labelSelector for pods
* upgrading k8 worker/master node via kubeadm
* enabling PSS/PSA and fixing issues and warnings highlighted by it.
* Cilium network policies
* enabling runtime class for gvisor/kata containers
* mounting service account token using serviceAccountToken projected volumes
* kube-bench for cis-benchmarking of master/worker node. specifically fixing the kubelet and restarting it successfully.
* container immutability
* creating tls secrets using key and certificate and mounting it ingress, bonus: redirecting http traffic to https when using nginx-controller for ingress
* etcd encryption at rest
* static manual analysis of DockerFile and k8 manifests ( look into common/known security best practices for it)
* verifying platform binaries
