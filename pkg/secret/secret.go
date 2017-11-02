package secret

import (
	"github.com/foxdalas/kube-cfssl/pkg/kubecfssl_const"

	k8sApi "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	k8sMeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sApiTyped "k8s.io/client-go/kubernetes/typed/core/v1"

	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/sirupsen/logrus"
	"time"
)

func New(client kubecfssl.KubeCfssl, namespace string, name string) *Secret {
	secret := &Secret{
		exists: true,
		kubecfssl: client,
	}

	var err error
	secret.SecretApi, err = client.KubeClient().CoreV1().Secrets(namespace).Get(name, k8sMeta.GetOptions{})
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			secret.SecretApi = &k8sApi.Secret{
				ObjectMeta: k8sMeta.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
			}
			secret.Log().Info("Attempting to create new secret")
			secret.exists = false
		} else {
			client.Log().Warn("Error while getting secret: ", err)
			client.Log().Warn("Retrying...")
			time.Sleep(time.Second * 60)
			return New(client, namespace, name)
		}
	}

	return secret
}

func (o *Secret) KubeCfssl() kubecfssl.KubeCfssl {
	return o.kubecfssl
}

func (o *Secret) Object() *k8sApi.Secret {
	return o.SecretApi
}

func (o *Secret) Exists() bool {
	return o.exists
}

func (o *Secret) client() k8sApiTyped.SecretInterface {
	return o.kubecfssl.KubeClient().CoreV1().Secrets(o.SecretApi.Namespace)
}

func (o *Secret) Log() *logrus.Entry {
	log := o.kubecfssl.Log().WithField("context", "secret")

	if o.SecretApi != nil && o.SecretApi.Name != "" {
		log = log.WithField("name", o.SecretApi.Name)
	}
	if o.SecretApi != nil && o.SecretApi.Namespace != "" {
		log = log.WithField("namespace", o.SecretApi.Namespace)
	}
	return log
}

func (o *Secret) tlsCertPem() (cert *x509.Certificate, err error) {
	key := kubecfssl.TLSCertKey

	certBytes, ok := o.SecretApi.Data[key]
	if !ok {
		err = fmt.Errorf("Data field '%s' not found", key)
		return
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		err = fmt.Errorf("Error parsing PEM certificate in '%s'", key)
		return
	}

	return x509.ParseCertificate(block.Bytes)
}

func (o *Secret) Save() (err error) {
	var obj *k8sApi.Secret
	if o.exists {
		obj, err = o.client().Update(o.SecretApi)
	} else {
		obj, err = o.client().Create(o.SecretApi)
	}
	if err != nil {
		o.Log().Warn("Error while storing secret: ", err)
		return
	}
	o.Log().Info("Secret successfully stored")
	o.SecretApi = obj
	return
}
