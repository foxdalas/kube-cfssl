package kubecfssl

import (
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"
	"sync"
	"time"
)

type KubeCfssl struct {
	version string
	log     *log.Entry

	//KubeCFSSL Variables
	address    string
	authKey    string
	csrConfig  string
	namespace  string
	secretName string

	checkInterval time.Duration
	//cfsslClient	cfkubeCfssl

	//Kubernets Variables
	kubeClient *kubernetes.Clientset
	kubeApiURL     string
	kubeNamespaces []string

	stopCh    chan struct{}
	waitGroup sync.WaitGroup
	workQueue *workqueue.Type
}
