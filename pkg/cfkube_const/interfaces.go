package cfkube

import (
	"github.com/sirupsen/logrus"
	"time"
	k8sApi "k8s.io/client-go/kubernetes"
	//k8sExtensions "k8s.io/api/extensions/v1beta1"
	k8sCore "k8s.io/api/core/v1"
)


type CFKube interface {
	KubeClient() *k8sApi.Clientset

	Version() string
	Log() *logrus.Entry

	CFKubeCheckInterval() time.Duration
	CFNamespace() string
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