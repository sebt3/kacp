# Kubernetes AuthenticationConfiguration Proxy

Kubernetes, since 1.30, allow for [multiple oidc providers](https://kubernetes.io/blog/2024/04/25/structured-authentication-moves-to-beta/).

In a multi-tenant configuration you might want to allow each tenant to have their own provider configuration. Since the configuration for the apiserver is a file, kacp is simple controller that aim at keeping in sync the file with all the declared providers in the cluster.

kacp aggregate the oidc configurations into an "AuthenticationConfiguration" for the apiserver.

## Requierements

- a kubernetes cluster with version &gt;=1.30
- `--authentication-config /etc/kubernetes/config/AuthenticationConfiguration.yaml` as argument for the apiserver.

_A side note_, the file has to exist and contain a valid configuration, here is the minimum file content:
```yaml
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt: []
```

### kubeadm configuration

Here is the configuration recommandation for kubeadm.
```yaml
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
apiServer:
  extraVolumes:
  - name: auth-cfg
    hostPath: /etc/kubernetes/config
    mountPath: /etc/kubernetes/config
  extraArgs:
    authentication-config: /etc/kubernetes/config/AuthenticationConfiguration.yaml
...
```
### Other kubernetes distributions

It should be possible to use kacp with any k8s distributions (k3s, k0s, kind...) but I'm not using them. Feel free to open an issue describing howto with your prefered distribution, I'll report the informations here.

## Installation

```shell
kubectl apply -k github.com/sebt3/kacp//deploy
```

## Example

For your cluster :
```yaml
apiVersion: kacp.solidite.fr/v1
kind: KubeAuthenticationConfiguration
metadata:
  name: your-domain
spec:
  issuer:
    audiences:
      - oidc-client-id
    url: https://auth.your-domain.com/application/o/kube-apiserver/
```

Associated kubeconfig:
```yaml
apiVersion: v1
kind: Config
current-context: remote
preferences: {}
contexts:
- context:
    cluster: remote
    namespace: default
    user: oidc
  name: remote
clusters:
- cluster:
    certificate-authority-data: <base64_k8s_certs>
    server: https://<api-server-url>
  name: remote
users:
- name: oidc
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - oidc-login
      - get-token
      - --oidc-issuer-url=https://auth.your-domain.com/application/o/kube-apiserver/
      - --oidc-client-id=kube-apiserver
      - --oidc-client-secret=<the secret>
      - --oidc-extra-scope=email
      - --oidc-extra-scope=profile
      - --oidc-extra-scope=groups
      command: kubectl
      env: null
      interactiveMode: IfAvailable
      provideClusterInfo: false
```