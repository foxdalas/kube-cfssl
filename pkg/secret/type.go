package secret

import (
	"github.com/foxdalas/cfssl-kube/pkg/kubecfssl_const"
	k8sApi "k8s.io/api/core/v1"
)

type Secret struct {
	exists    	bool
	SecretApi 	*k8sApi.Secret
	kubecfssl 	kubecfssl.KubeCfssl
}
