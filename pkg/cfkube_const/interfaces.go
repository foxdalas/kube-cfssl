package cfkube

import (
	"github.com/sirupsen/logrus"
	k8sCore "k8s.io/api/core/v1"
	k8sApi "k8s.io/client-go/kubernetes"
	"time"
)

type CFKube interface {
	KubeClient() *k8sApi.Clientset

	Version() string
	Log() *logrus.Entry

	CFKubeCheckInterval() time.Duration
	CFNamespace() string
	//ValidateTLS() bool
}

type Cfssl interface {
	GetCertificate() string
	CreateKey() []byte
}

type Secret interface {
	Object() *k8sCore.Secret
	KubeLego() CFKube
	Exists() bool
	Save() error
	TlsDomains() ([]string, error)
	TlsDomainsInclude(domains []string) bool
	TlsExpireTime() (time.Time, error)
}
