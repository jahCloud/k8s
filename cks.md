- [CKS](#cks)
  - [Helpful Tips](#helpful-tips)
  - [Introduction](#introduction)
  - [Cloud Native Security](#cloud-native-security)
    - [Area of Concern for Kubernetes Infrastructure](#area-of-concern-for-kubernetes-infrastructure)
    - [Area of Concern for Workload Security](#area-of-concern-for-workload-security)
    - [Area of Concern for Containers](#area-of-concern-for-containers)
    - [Area of Concern for Code](#area-of-concern-for-code)
  - [Pod Security Standards](#pod-security-standards)
    - [What's the difference between a security policy and a security context?](#whats-the-difference-between-a-security-policy-and-a-security-context)
  - [Network Policy](#network-policy)
  - [Kubernetes API](#kubernetes-api)
    - [Transport Security](#transport-security)
    - [Authentication](#authentication)
    - [Authorization](#authorization)
      - [RBAC](#rbac)
    - [Admission Control](#admission-control)
    - [Certificate Management](#certificate-management)
      - [Kubernetes signers](#kubernetes-signers)
    - [Managing Service Accounts](#managing-service-accounts)
      - [ServiceAccount Admission Controller](#serviceaccount-admission-controller)
      - [Token Controller](#token-controller)
      - [ServiceAccount controller](#serviceaccount-controller)
  - [Pod Security Policy](#pod-security-policy)
  - [Secret Encryption](#secret-encryption)
  - [Auditing](#auditing)
  - [AppArmor](#apparmor)
  - [Runtime Class](#runtime-class)

# CKS

## Helpful Tips

- Common paths:

```

# Certificate path
/etc/kubernetes/pki/

# kubelet certificate path
/var/lib/kubelet/pki/

# kubernetes scheduler
/etc/kubernetes/scheduler.conf

# kubernetes controller manager
/etc/kubernetes/controller-manager.conf

# kubernetes api server manifest
/etc/kubernetes/manifests/kube-apiserver.yaml

# kubelet. Can use as kubeconfig as well
/etc/kubernetes/kubelet.conf
/etc/default/kubelet
/var/lib/kubelet/config.yaml
/etc/systemd/system/kubelet.service.d/

# certificate mountpoint inside the pod
/run/secrets/kubernetes.io/serviceaccount

# etcd secret path
/registry/secrets/<namespace>/<secret-name>

# pod logs path
/var/log/pods

# admission controller path
/etc/kubernetes/admission/
```

- To generate TLS

```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

- To retrieve container volume

```
docker cp <container-name>:/ <folder>
```

- To create role & rolebinding

```
kubectl create role <role-name> --verb=get --resource=secrets
kubectl create rolebinding <rolebinding-name> --role=<role-name> --user=<user>
```

- To test user permission

```
kubectl auth can-i <verb> <obj> --as <user>
kubectl auth can-i <verb> <obj> --as system:serviceaccount:<namespace>:<service-account-name>

```

- Approve certificate

```
kubectl certificate approve <certificate-signing-request-name>

# certificate in .status.certificate
```

- Create kubeconfig with certificate info

```
kubectl config set-credentials <user> --client-key=<key-name> --client-certificate=<cert-name>

# add --embed-certs for in-line certificate

kubectl config view
```

- To read secret from etcd

```
# Check api-server manifest to get the certs

export cert=/etc/kubernetes/pki/apiserver-etcd-client.crt
export key=/etc/kubernetes/pki/apiserver-etcd-client.key
export ca=/etc/kubernetes/pki/etcd/ca.crt

ETCDCTL_API=3 etcdctl --cert $cert --key $key --cacert $ca get /registry/secrets/<namespace>/<secret-name>
```

- To generate yaml template

```
kubectl run <name> --image=nginx -o yaml --dry-run=client > file.yaml
```

- Tools
  - pstree -p
  - strace -cw


- docker run with apparmor

```
docker run --security-opt apparmor=<profile-name> <image-name>
```

- Call kubernetes api with service account token

```
curl https://kubernetes.default/api/v1/namespaces/restricted/secrets -H "Authorization: Bearer $(cat /run/secrets/kubernetes.io/serviceaccount/token)" -k
```

- To find syscalls

```
strace -p <PID>
```

## Introduction

Just a place to write down any notes for CKS journey
Offical document: https://kubernetes.io/docs/concepts/security/

## Cloud Native Security

![](https://d33wubrfki0l68.cloudfront.net/50846f7aa12f39c374f4e5ace769efe26a92f7d7/8fe83/images/docs/4c.png)

### Area of Concern for Kubernetes Infrastructure

- Network access to API Server (Control plane)
- Network access to Nodes (nodes)
- Kubernetes access to Cloud Provider API
- Access to etcd	
- etcd Encryption

### Area of Concern for Workload Security

- RBAC Authorization (Access to the Kubernetes API)	
- Authentication
- Application secrets management (and encrypting them in etcd at rest)
- Pod Security Policies
- Quality of Service (and Cluster resource management)
- Network Policies
- TLS For Kubernetes Ingress

### Area of Concern for Containers

- Container Vulnerability Scanning and OS Dependency Security
- Image Signing and Enforcement
- Disallow privileged users
- Use container runtime with stronger isolation

### Area of Concern for Code

- Access over TLS only
- Limiting port ranges of communication
- 3rd Party Dependency Security
- Static Code Analysis
- Dynamic probing attacks

## Pod Security Standards

Policies:
- Privileged
- Baseline
- Restricted

### What's the difference between a security policy and a security context?

[Security Contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) configure Pods and Containers at runtime. Security contexts are defined as part of the Pod and container specifications in the Pod manifest, and represent parameters to the container runtime.

Security policies are control plane mechanisms to enforce specific settings in the Security Context, as well as other parameters outside the Security Context. As of February 2020, the current native solution for enforcing these security policies is [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) - a mechanism for centrally enforcing security policy on Pods across a cluster. Other alternatives for enforcing security policy are being developed in the Kubernetes ecosystem, such as [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper).

## Network Policy

The entities that a Pod can communicate with are identified through a combination of the following 3 identifiers:

- Other pods that are allowed (exception: a pod cannot block access to itself)
- Namespaces that are allowed
- IP blocks (exception: traffic to and from the node where a Pod is running is always allowed, regardless of the IP address of the Pod or the node)

- Multiple np with the same name will be merged
- Default deny

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-np
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  egress:
    - to:
      ports:
        - port: 53
          protocol: TCP
        - port: 53
          protocol: UDP
```


## Kubernetes API

![](https://d33wubrfki0l68.cloudfront.net/673dbafd771491a080c02c6de3fdd41b09623c90/50100/images/docs/admin/access-control-overview.svg)

![kubectl proxy](https://imgur.com/NG5zevP.png)

![kubectl port-forward](https://imgur.com/x2ZGlUM.png)


> anonymous access is used for kube api server healthcheck, so be careful when disabling it.
> Toggle with `--anonymous-auth=false`

> Insecure port `--insecure-port=8080`

> Manual access kube api. `curl <ENDPOINT> --cacert <ca> --cert <cert> --key <key>` (info taken from kubeconfig)
> 

### Transport Security

- API serves on `localhost:8080`, no TLS, bypass authentication & authorization.
- API serves on port `6443` (proxied from public `443`), protected by TLS.

- If your cluster uses a private certificate authority, you need a copy of that CA certificate configured into your `~/.kube/config` on the client, so that you can trust the connection and be confident it was not intercepted.

### Authentication

- HTTP requests need to go through authenticator modules. See more on [authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
  - Failed --> 401
  - Successful --> `username` mapped --> reusable for subsequent steps

- Kubernetes does not have `User` object or store user information

![user](https://imgur.com/kkOglNG.png)

- Two categories of users: 
  - Normal users not managed by Kubernetes
    - Determines the username from the common name field in the `subject` of the cert (e.g., "/CN=bob")
  - Service accounts managed by Kubernetes
    - Are bound to specific namespaces, and created automatically by the API server or manually through API calls
    - Are tied to a set of credentials stored as Secrets, which are mounted into pods allowing in-cluster processes to talk to the Kubernetes API.

- API requests are tied to either a normal user or a service account, or are treated as `anonymous requests`

- Kubernetes uses client certificates, bearer tokens, an authenticating proxy, or HTTP basic auth to authenticate API requests through authentication plugins. Plugins attempt to associate the following attributes with the request: username, uid, groups, extra fields
  - X509 client certs: enabled by passing the `--client-ca-file=SOMEFILE` option to API server
  - Static token file: given the `--token-auth-file=SOMEFILE` option
  - Bearer token: the API server expects an `Authorization` header with a value of `Bearer THETOKEN`
  - Bootstrap token: See [link](https://kubernetes.io/docs/reference/access-authn-authz/bootstrap-tokens/)
  - Service account token: Are perfectly valid to use outside the cluster and can be used to create identities for long standing jobs that wish to talk to the Kubernetes API.
  - OpenID connect token: 
  ![](https://i.imgur.com/xDlwoDP.png)
  - Webhook token:
    - When a client attempts to authenticate with the API server using a bearer token as discussed above, the authentication webhook POSTs a JSON-serialized `TokenReview` object containing the token to the remote service.
    - The remote service must return a response using the same TokenReview API version that it received


- The API server does not guarantee the order authenticators run in.

- A user can act as another user through impersonation headers

```bash
kubectl drain mynode --as=superman --as-group=system:masters
```

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]
```

### Authorization

- A request must include the username of the requester, the requested action, and the object affected by the action. The request is authorized if an existing policy declares that the user has permissions to complete the requested action. See more on [authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)

- Sample policy:

```json
{
    "apiVersion": "abac.authorization.kubernetes.io/v1beta1",
    "kind": "Policy",
    "spec": {
        "user": "bob",
        "namespace": "projectCaribou",
        "resource": "pods",
        "readonly": true
    }
}
```

- Sample request review:

```json
{
  "apiVersion": "authorization.k8s.io/v1beta1",
  "kind": "SubjectAccessReview",
  "spec": {
    "resourceAttributes": {
      "namespace": "projectCaribou",
      "verb": "get",
      "group": "unicorn.example.org",
      "resource": "pods"
    }
  }
}
```

- `bob` will be allowed to get `pod` resources within `projectCaribou` namespace

- Denied --> 403
  
- Non-resource requests Requests to endpoints other than /api/v1/... or /apis/<group>/<version>/... are considered "non-resource requests", and use the lower-cased HTTP method of the request as the verb

- A user granted permission to create pods (or controllers that create pods) in the namespace can: read all secrets in the namespace; read all config maps in the namespace; and impersonate any service account in the namespace and take any action the account could take.

- Authorization modules:
  - ABAC mode
  - RBAC Mode
  - Webhook mode

#### RBAC

- After you create a binding, you cannot change the Role or ClusterRole that it refers to. If you try to change a binding's roleRef, you get a validation error. If you do want to change the roleRef for a binding, you need to remove the binding object and create a replacement.

- You can aggregate several ClusterRoles into one combined ClusterRole. A controller, running as part of the cluster control plane, watches for ClusterRole objects with an aggregationRule set. The `aggregationRule` defines a label selector that the controller uses to match other ClusterRole objects that should be combined into the rules field of this one. See [link](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#aggregated-clusterroles)

- At each start-up, the API server updates default cluster roles with any missing permissions, and updates default cluster role bindings with any missing subjects. This allows the cluster to repair accidental modifications, and helps to keep roles and role bindings up-to-date as permissions and subjects change in new Kubernetes releases.

### Admission Control

- [Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) modules can:
  - Modify or reject requests
  - Access the contents of the object that is being created or modified

- Admission controllers `do not` act on requests that merely `read` objects 

- 1 module failed --> immediately rejected

![admission controller](https://imgur.com/gZbH8ke.png)


### Certificate Management

- A CertificateSigningRequest (CSR) resource is used to request that a certificate be signed by a denoted signer
- The signing controller then updates the CertificateSigningRequest, storing the new certificate into the status.certificate field of the existing CertificateSigningRequest object


#### Kubernetes signers

- `kubernetes.io/kube-apiserver-client`: signs certificates that will be honored as client certificates by the API server. Never auto-approved by kube-controller-manager.
- `kubernetes.io/kube-apiserver-client-kubelet`: signs client certificates that will be honored as client certificates by the API server. May be auto-approved by kube-controller-manager.
- `kubernetes.io/kubelet-serving`: signs serving certificates that are honored as a valid kubelet serving certificate by the API server, but has no other guarantees. Never auto-approved by kube-controller-manager
- `kubernetes.io/legacy-unknown`: has no guarantees for trust at all. Some third-party distributions of Kubernetes may honor client certificates signed by it. The stable CertificateSigningRequest API (version certificates.k8s.io/v1 and later) does not allow to set the signerName as `kubernetes.io/legacy-unknown`. Never auto-approved by kube-controller-manager.

For TLS certificates. See [link](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/)



### Managing Service Accounts

#### ServiceAccount Admission Controller

- If the pod does not have a ServiceAccount set, it sets the ServiceAccount to default.
- It ensures that the ServiceAccount referenced by the pod exists, and otherwise rejects it.
- If the pod does not contain any ImagePullSecrets, then ImagePullSecrets of the ServiceAccount are added to the pod.
- It adds a volume to the pod which contains a token for API access.
- It adds a volumeSource to each container of the pod mounted at `/var/run/secrets/kubernetes.io/serviceaccount`.

#### Token Controller

- watches ServiceAccount creation and creates a corresponding ServiceAccount token Secret to allow API access.
- watches ServiceAccount deletion and deletes all corresponding ServiceAccount token Secrets.
- watches ServiceAccount token Secret addition, and ensures the referenced ServiceAccount exists, and adds a token to the Secret if needed.
- watches Secret deletion and removes a reference from the corresponding ServiceAccount if needed.

#### ServiceAccount controller

- manages the ServiceAccounts inside namespaces
- ensures a ServiceAccount named "default" exists in every active namespace

## Pod Security Policy

- Necessary role to use psp
```yaml
...
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - example
...
```

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  privileged: false  # Don't allow privileged pods!
  # The rest fills in some required fields.
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
  ```

- PodSecurityPolicies which allow the pod as-is, without changing defaults or mutating the pod, are preferred. The order of these non-mutating PodSecurityPolicies doesn't matter.
- If the pod must be defaulted or mutated, the first PodSecurityPolicy (ordered by name) to allow the pod is selected.

## Secret Encryption

See [link](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)

## Auditing

See [link](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)

Each request can be recorded with an associated stage. The defined stages are:

- `RequestReceived` - The stage for events generated as soon as the audit handler receives the request, and before it is delegated down the handler chain.
- `ResponseStarted` - Once the response headers are sent, but before the response body is sent. This stage is only generated for long-running requests (e.g. watch).
- `ResponseComplete` - The response body has been completed and no more bytes will be sent.
- `Panic` - Events generated when a panic occurred.

**The first matching rule** sets the audit level of the event. The defined audit levels are:

- `None` - don't log events that match this rule.
- `Metadata` - log request metadata (requesting user, timestamp, resource, verb, etc.) but not request or response body.
- `Request` - log event metadata and request body but not response body. This does not apply for non-resource requests.
- `RequestResponse` - log event metadata, request and response bodies. This does not apply for non-resource requests.

```yaml
# Log all requests at the Metadata level.
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
```

Enable in kube-apiserver

```
    - --audit-policy-file=/etc/kubernetes/audit/policy.yaml       # add
    - --audit-log-path=/etc/kubernetes/audit/logs/audit.log       # add
    - --audit-log-maxsize=500                                     # add
    - --audit-log-maxbackup=5                                     # add

    volumeMounts:
      - mountPath: /etc/kubernetes/audit      # add
      name: audit                           # add

        volumes:
        - hostPath:                               # add
            path: /etc/kubernetes/audit           # add
            type: DirectoryOrCreate               # add
          name: audit                             # add
```
## AppArmor

- Enabled on container-based via annotations

```yaml
container.apparmor.security.beta.kubernetes.io/<container_name>: <profile_ref>
```

## Runtime Class

You can set a different RuntimeClass between different Pods to provide a balance of performance versus security. For example, if part of your workload deserves a high level of information security assurance, you might choose to schedule those Pods so that they run in a container runtime that uses hardware virtualization. You'd then benefit from the extra isolation of the alternative runtime, at the expense of some additional overhead.

- Configure the CRI implementation on nodes (runtime dependent)
- Create the corresponding RuntimeClass resources

```yaml
apiVersion: node.k8s.io/v1  # RuntimeClass is defined in the node.k8s.io API group
kind: RuntimeClass
metadata:
  name: myclass  # The name the RuntimeClass will be referenced by
  # RuntimeClass is a non-namespaced resource
handler: myconfiguration  # The name of the corresponding CRI configuration

---

apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  runtimeClassName: myclass
```

## Open Policy Agent

- Constraint Template `templates.gatekeeper.sh/v1beta1`
- Constraint `constraints.gatekeeper.sh/v1beta1`
- Audit
> The audit functionality enables periodic evaluations of replicated resources against the `Constraints` enforced in the cluster to detect pre-existing misconfigurations. Gatekeeper stores audit results as violations listed in the status field of the relevant `Constraint`.
- Config `config.gatekeeper.sh/v1alpha1`

## Attack Matrix

![](https://www.microsoft.com/security/blog/wp-content/uploads/2020/04/k8s-matrix.png)
