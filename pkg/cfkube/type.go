package cfkube

import (
	log "github.com/sirupsen/logrus"
	"sync"
	"k8s.io/client-go/util/workqueue"
	"time"
	"k8s.io/client-go/kubernetes"
)

type CFKube struct {
	version string
	log 			*log.Entry

	cfAddress 		string
	cfAuthKey 		string
	cfCSRConfig 	[]byte
	cfNamespace 	string
	cfSecretName	string

	cfCheckInterval time.Duration
	//cfsslClient	cfkubeCfssl

	kubeClient  	*kubernetes.Clientset

	cfKubeApiURL 	string
	cfKubeNamespaces []string

	stopCh 			chan struct{}
	waitGroup 		sync.WaitGroup
	workQueue 		*workqueue.Type
}