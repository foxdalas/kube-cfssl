package cfkube

import (
	"errors"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func (cf *CFKube) InitKube() error {
	// Try in cluster client first
	config, err := rest.InClusterConfig()
	if err != nil {
		cf.Log().Warnf("failed to create in-cluster client: %v.", err)

		// fall back to kubeconfig
		// TODO: Link to kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", "/Users/fox/.kube/config")
		if err != nil {
			cf.Log().Warnf("failed to create kubeconfig client: %v.", err)
			return errors.New("kube init failed as both in-cluster and dev connection unavailable")
		}
	}
	cf.Log().Info("connecting to kubernetes api: ", config.Host)

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	version, err := kubeClient.ServerVersion()
	if err != nil {
		return err
	}
	cf.Log().Infof("successfully connected to kubernetes api %s", version.String())

	cf.kubeClient = kubeClient
	return nil
}

func (cf *CFKube) Namespace() string {
	return cf.cfNamespace
}