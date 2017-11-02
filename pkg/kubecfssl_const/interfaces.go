package kubecfssl

import (
	"github.com/sirupsen/logrus"
	k8sCore "k8s.io/api/core/v1"
	k8sApi "k8s.io/client-go/kubernetes"
	"time"
)

type KubeCfssl interface {
	KubeClient() *k8sApi.Clientset

	Version() string
	Log() *logrus.Entry

	KubeCheckInterval() time.Duration
	Namespace() string
	//ValidateTLS() bool
}

type Cfssl interface {
	GetCertificate() string
	CreateKey() []byte
}

type Secret interface {
	Object() *k8sCore.Secret
	KubeLego() KubeCfssl
	Exists() bool
	Save() error
	TlsDomains() ([]string, error)
	TlsDomainsInclude(domains []string) bool
	TlsExpireTime() (time.Time, error)
}
