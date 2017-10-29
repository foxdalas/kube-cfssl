package secret

import (
	"github.com/foxdalas/cfssl-kube/pkg/cfkube_const"
	k8sApi "k8s.io/api/core/v1"
)

type Secret struct {
	SecretApi *k8sApi.Secret
	exists    bool
	cfkube    cfkube.CFKube
}
