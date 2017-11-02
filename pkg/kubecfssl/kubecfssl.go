package kubecfssl

import (
	"errors"
	"github.com/foxdalas/kube-cfssl/pkg/kubecfssl_const"
	"github.com/foxdalas/kube-cfssl/pkg/cfssl"
	"github.com/foxdalas/kube-cfssl/pkg/secret"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var _ kubecfssl.KubeCfssl = &KubeCfssl{}

func New(version string) *KubeCfssl {
	return &KubeCfssl{
		version:   version,
		log:       makeLog(),
		stopCh:    make(chan struct{}),
		waitGroup: sync.WaitGroup{},
	}
}

func (kc *KubeCfssl) Log() *log.Entry {
	return kc.log
}

func (kc *KubeCfssl) Init() {
	kc.Log().Infof("kube-cfssl %s starting", kc.version)

	// handle sigterm correctly
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-c
		logger := kc.Log().WithField("signal", s.String())
		logger.Debug("received signal")
		kc.Stop()
	}()

	// parse env vars
	err := kc.paramsCF()
	if err != nil {
		kc.Log().Fatal(err)
	}

	if _, err := os.Stat(kc.csrConfig); os.IsNotExist(err) {
		kc.Log().Fatalf("CSR Configuration file not found in %s", kc.csrConfig)
	}

	err = kc.InitKube()
	if err != nil {
		kc.Log().Fatal(err)
	}

	kc.Log().Infoln("Periodically check start")
	ticker := time.NewTicker(kc.checkInterval)

	go func() {
		for {
			timestamp := time.Now()
			kc.Log().Infof("Periodically check certificates at %s", timestamp)
			for _, namespace := range kc.kubeNamespaces {

				kc.namespace = namespace
				kc.secretName = "cfssl-tls-secret"

				kc.Log().Infoln("Checking namespace:", namespace)

				if !kc.checkSecret() {
					kc.SaveSecret()
				}
			}
			<-ticker.C
		}
	}()

	<-kc.stopCh
	ticker.Stop()
	kc.Log().Infof("exiting")
	kc.waitGroup.Wait()

}

func (kc *KubeCfssl) checkSecret() bool {
	s := secret.New(kc, kc.namespace, kc.secretName)

	s.SecretApi.Name = kc.secretName
	s.SecretApi.Namespace = kc.namespace

	if !s.Exists() {
		kc.Log().Printf("Secret for namespace %s is not exist", kc.namespace)
		return false
	} else {
		kc.Log().Printf("Secret for namespace %s already exist", kc.namespace)
		if s.Validate() != 0 {
			if s.Validate() > 1 {
				return false
			}
			kc.Log().Println("Certificate validation problem.")
		}
	}
	return true
}

func makeLog() *log.Entry {
	logtype := strings.ToLower(os.Getenv("LOG_TYPE"))
	if logtype == "" {
		logtype = "text"
	}

	if logtype == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else if logtype == "text" {
		log.SetFormatter(&log.TextFormatter{})
	} else {
		log.WithField("logtype", logtype).Fatal("Given logtype was not valid, check LOG_TYPE configuration")
		os.Exit(1)
	}

	loglevel := strings.ToLower(os.Getenv("LOG_LEVEL"))
	if len(loglevel) == 0 {
		log.SetLevel(log.InfoLevel)
	} else if loglevel == "debug" {
		log.SetLevel(log.DebugLevel)
	} else if loglevel == "info" {
		log.SetLevel(log.InfoLevel)
	} else if loglevel == "warn" {
		log.SetLevel(log.WarnLevel)
	} else if loglevel == "error" {
		log.SetLevel(log.ErrorLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	return log.WithField("context", "kube-cfssl")
}

func (kc *KubeCfssl) Version() string {
	return kc.version
}

func (kc *KubeCfssl) Stop() {
	kc.Log().Info("shutting things down")
	close(kc.stopCh)
}

func (kc *KubeCfssl) KubeApiURL() string {
	return kc.kubeApiURL
}

func (kc *KubeCfssl) KubeClient() *kubernetes.Clientset {
	return kc.kubeClient
}

func (kc *KubeCfssl) cfsslSecret() *secret.Secret {
	return secret.New(kc, kc.namespace, kc.secretName)
}



func (kc *KubeCfssl) paramsCF() error {

	kc.address = os.Getenv("CFSSL_ADDRESS")
	if len(kc.address) == 0 {
		return errors.New("Please provide an address for CFSSL Server in CFSSL_ADDRESS")
	}

	kc.authKey = os.Getenv("CFSSL_AUTH_KEY")
	if len(kc.authKey) == 0 {
		return errors.New("Please provide the secret key via environment variable CFSSL_AUTH_KEY ")
	}

	checkIntervalString := os.Getenv("CHECK_INTERVAL")
	if len(checkIntervalString) == 0 {
		kc.checkInterval = 1 * time.Minute
	}
	kc.csrConfig = os.Getenv("CSR_CONFIG")
	if len(kc.csrConfig) == 0 {
		return errors.New("Please provide the secret key via environment variable CSR_CONFIG")
	}

	kc.kubeApiURL = os.Getenv("KUBE_API_URL")
	if len(kc.kubeApiURL) == 0 {
		kc.kubeApiURL = "http://127.0.0.1:8080"
	}

	kc.kubeNamespaces = strings.Split(os.Getenv("NAMESPACES"), ",")
	if len(kc.kubeNamespaces) == 0 {
		return errors.New("Please provide the namespaces via environment variable NAMESPACES (default,test,production)")
	}

	kc.kubeSecretName = os.Getenv("SECRET")
	if len(kc.kubeSecretName) == 0 {
		kc.kubeSecretName = "cfssl-tls-secret"
	}

	return nil
}

func (kc *KubeCfssl) SaveSecret() error {
	s := kc.cfsslSecret()
	cf := cfssl.New(kc)
	s.SecretApi.Data = cf.GetCertificate(kc.address, kc.authKey, kc.csrConfig)

	return s.Save()
}