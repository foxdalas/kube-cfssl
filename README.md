# kube-cfssl
CFSSL Certificates generator for Kubernetes

[![Docker Repository on Quay](https://quay.io/repository/foxdalas/kube-cfssl/status "Docker Repository on Quay")](https://quay.io/repository/foxdalas/kube-cfssl)
[![Docker Pulls](https://img.shields.io/docker/pulls/foxdalas/kube-cfssl.svg?maxAge=604800)](https://hub.docker.com/r/foxdalas/kube-cfssl/)
[![CircleCI](https://circleci.com/gh/foxdalas/kube-cfssl.svg?style=svg)](https://circleci.com/gh/foxdalas/kube-cfssl)

## Usage

### RBAC

```
kubectl apply -f https://raw.githubusercontent.com/foxdalas/kube-cfssl/master/dist/kube-cfssl-rbac.yml
```

### Deployment
```
kubectl apply -f https://raw.githubusercontent.com/foxdalas/kube-cfssl/master/dist/kube-cfssl-deploy.yml
```

### CSR Example
```
---
certificate_request:
hosts:
- example.com
profile: peer
subject:
  names:
  - C: GB
    L: London
    O: Clip LLP
    OU: IT
```