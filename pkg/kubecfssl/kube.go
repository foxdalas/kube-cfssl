package kubecfssl

import (
	"errors"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func (kc *KubeCfssl) InitKube() error {
	// Try in cluster client first
	config, err := rest.InClusterConfig()
	if err != nil {
		kc.Log().Warnf("failed to create in-cluster client: %v.", err)

		// fall back to kubeconfig
		// TODO: Link to kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", "/Users/fox/.kube/config")
		if err != nil {
			kc.Log().Warnf("failed to create kubeconfig client: %v.", err)
			return errors.New("kube init failed as both in-cluster and dev connection unavailable")
		}
	}
	kc.Log().Info("connecting to kubernetes api: ", config.Host)

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	version, err := kubeClient.ServerVersion()
	if err != nil {
		return err
	}
	kc.Log().Infof("successfully connected to kubernetes api %s", version.String())

	kc.kubeClient = kubeClient
	return nil
}

func (kc *KubeCfssl) Namespace() string {
	return kc.namespace
}
