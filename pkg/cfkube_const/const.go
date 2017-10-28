package cfkube

import (
	k8sApi "k8s.io/api/core/v1"
)

const RsaKeySize = 2048

const TLSCertKey = k8sApi.TLSCertKey
const TLSPrivateKeyKey = k8sApi.TLSPrivateKeyKey
