package kubecfssl

import (
	k8sApi "k8s.io/api/core/v1"
)

const RsaKeySize = 2048
const TLSCertKey = k8sApi.TLSCertKey
const TLSPrivateKeyKey = k8sApi.TLSPrivateKeyKey
const ExpireThreshold = 604800
const PKIUri = "/api/v1/cfssl/"


const CertificateName = "crt.pem"
const CertificateKeyName = "crt.key"
const RootCertificateName = "ca.pem"
const BundleCertificateName = "bundle.pem"