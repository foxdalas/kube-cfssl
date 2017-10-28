package cfkube

import (
	"errors"
	"sync"
	cfkube "cfssl-kube/pkg/cfkube_const"
	"cfssl-kube/pkg/secret"
	log "github.com/sirupsen/logrus"
	"strings"
	"os"
	"os/signal"
	"syscall"
	"time"
	"cfssl-kube/pkg/cfssl"
	"k8s.io/client-go/kubernetes"
)

var _ cfkube.CFKube = &CFKube{}

func New(version string) *CFKube {
	return &CFKube{
		version:   version,
		log:       makeLog(),
		stopCh:    make(chan struct{}),
		waitGroup: sync.WaitGroup{},
	}
}

func (cf *CFKube) Log() *log.Entry {
	return cf.log
}

func (cf *CFKube) Init() {
	cf.Log().Infof("cfkube %s starting", cf.version)

	// handle sigterm correctly
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-c
		logger := cf.Log().WithField("signal", s.String())
		logger.Debug("received signal")
		cf.Stop()
	}()

	// parse env vars
	err := cf.paramsCF()
	if err != nil {
		cf.Log().Fatal(err)
	}



	err = cf.InitKube()
	if err != nil {
		cf.Log().Fatal(err)
	}


	cf.Log().Infoln("Periodically check start")
	ticker := time.NewTicker(cf.cfCheckInterval)
	cs := cfssl.New(cf)
	go func() {
		for timestamp := range ticker.C {
			cf.Log().Infof("Periodically check certificates at %s", timestamp)
			for _, namespace := range cf.cfKubeNamespaces {
				cf.Log().Infoln("Checking namespace: ", namespace)
				s := secret.New(cf, namespace, "cfssl-tls-secret")
				//s.SecretApi.Data["test"] = []byte("ololo")

				if !s.Exists() {
					cf.Log().Printf("Secret for namespace %s is not exist", namespace)

				}

			}

			//Generating new data
			//TODO: Add certificate check in secret
			cf.Log().Infoln(cs.GetCertificate(cf.cfAddress, cf.cfAuthKey, cf.cfCSRConfig, cs.CreateKey()))
		}
	}()

	<-cf.stopCh
	ticker.Stop()
	cf.Log().Infof("exiting")
	cf.waitGroup.Wait()

}

func makeLog() *log.Entry {
	logtype := strings.ToLower(os.Getenv("CFKUBE_LOG_TYPE"))
	if logtype == "" {
		logtype = "text"
	}

	if logtype == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else if logtype == "text" {
		log.SetFormatter(&log.TextFormatter{})
	} else {
		log.WithField("logtype", logtype).Fatal("Given logtype was not valid, check CFKUBELOG_TYPE configuration")
		os.Exit(1)
	}

	loglevel := strings.ToLower(os.Getenv("LEGO_LOG_LEVEL"))
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
	return log.WithField("context", "cfkube")
}


func (cf *CFKube) Version() string {
	return cf.version
}

func (cf *CFKube) Stop() {
	cf.Log().Info("shutting things down")
	close(cf.stopCh)
}

func (cf *CFKube) CFNamespace() string {
	return cf.cfNamespace
}

func (cf *CFKube) CFKubeCheckInterval() time.Duration {
	return cf.cfCheckInterval
}

func (cf *CFKube) CFKubeApiURL() string {
	return cf.cfKubeApiURL
}

func (cf *CFKube) KubeClient() *kubernetes.Clientset {
	return cf.kubeClient
}

func (cf *CFKube) cfsslSecret() *secret.Secret {
	return secret.New(cf, cf.cfNamespace, cf.cfSecretName)
}


func (cf *CFKube) paramsCF() error {

	cf.cfAddress = os.Getenv("CFKUBE_CFSSL_ADDRESS")
	if len(cf.cfAddress) == 0 {
		return errors.New("Please provide an address for CFSSL Server in CFKUBE_CFSSL_ADDRESS")
	}

	cf.cfAuthKey = os.Getenv("CFKUBE_CFSSL_AUTH_KEY")
	if len(cf.cfAuthKey) == 0 {
		return errors.New("Please provide the secret key via environment variable CFKUBE_CFSSL_AUTH_KEY ")
	}

	checkIntervalString := os.Getenv("CFKUBE_CHECK_INTERVAL")
	if len(checkIntervalString) == 0 {
		cf.cfCheckInterval = 1 * time.Minute
	}
	cf.cfCSRConfig = []byte(os.Getenv("CFKUBE_CFSSL_CSR"))
	if len(cf.cfCSRConfig) == 0 {
		return errors.New("Please provide the secret key via environment variable CFKUBE_CFSSL_CSR ")
	}

	cf.cfKubeApiURL = os.Getenv("CFKUBE_KUBE_API_URL")
	if len(cf.cfKubeApiURL) == 0 {
		cf.cfKubeApiURL = "http://127.0.0.1:8080"
	}

	cf.cfKubeNamespaces = strings.Split(os.Getenv("CFKUBE_NAMESPACES"),",")
	if len(cf.cfKubeNamespaces) == 0 {
		return errors.New("Please provide the namespaces via environment variable CFKUBE_NAMESPACES (default,test,production)")
	}

	return nil
}