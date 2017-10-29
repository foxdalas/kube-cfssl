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
	"encoding/pem"
	"crypto/x509"
	"crypto/tls"
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
				cf.cfNamespace = namespace
				cf.cfSecretName = "cfssl-tls-secret"
				cf.Log().Infoln("Checking namespace: ", cf.cfNamespace)


				s := secret.New(cf, namespace, "cfssl-tls-secret")

				s.SecretApi.Name = "cfssl-tls-secret"
				s.SecretApi.Namespace = namespace

				if !s.Exists() {
					cf.Log().Printf("Secret for namespace %s is not exist", cf.cfNamespace)
					cf.SaveSecret(cs.GetCertificate(cf.cfAddress, cf.cfAuthKey, cf.cfCSRConfig, cs.CreateKey()))
				} else {
					cf.Log().Printf("Secret for namespace %s already exist", cf.cfNamespace)
					validate := cf.ValidateTLS(s.SecretApi.Data["ca.pem"], s.SecretApi.Data["crt.pem"], s.SecretApi.Data["crt.key"])
					if !validate {
						cf.SaveSecret(cs.GetCertificate(cf.cfAddress, cf.cfAuthKey, cf.cfCSRConfig, cs.CreateKey()))
					}
				}
			}
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

func (cf *CFKube) SaveSecret(data map[string][]byte) error {
	s := cf.cfsslSecret()
	s.SecretApi.Data = data
	return s.Save()
}

func (c *CFKube) ValidateTLS(caByte []byte, certByte []byte, keyByte []byte) bool {
	check := true

	block, _ := pem.Decode(certByte)
	if block == nil {
		c.Log().Errorln("Failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.Log().Printf("Failed to parse certificate: " + err.Error())
	}
	if (cert.NotAfter.Unix() - time.Now().Unix()) < int64(cfkube.ExpireThreshold) {
		c.Log().Warningf("Certificate expire date > Threshold ")
		check = false
	} else {
		c.Log().Infoln("Certificate expire date is OK")
	}

	_, err = tls.X509KeyPair(certByte, keyByte)
	if err != nil {
		c.Log().Warningln("Certificate cert/key is mismatch")
		check = false
	} else {
		c.Log().Infoln("Certificate cert/key is OK")
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caByte)
	if !ok {
		log.Warnln("Failed to parse root certificate")
		check = false
	}

	for _, dnsName := range cert.DNSNames {
		opts := x509.VerifyOptions{
			DNSName: dnsName,
			Roots:   roots,
		}
		c.Log().Infof("Validating certificate for DNS name: %s",dnsName )
		if _, err := cert.Verify(opts); err != nil {
			c.Log().Warnf("failed to verify certificate: " + err.Error())
			check = false
		} else {
			c.Log().Infof("Certificate is valid for %s", dnsName)
		}
	}

	if check {
		//Information about certificate
		c.Log().Infof("Certificate is valid. Expire Date %s", cert.NotAfter)
	}

	return check
}