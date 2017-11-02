package kubecfssl

import (
	"k8s.io/client-go/util/workqueue"
)

func (kc *KubeCfssl) WatchReconfigure() {

	kc.workQueue = workqueue.New()

	// handle worker shutdown
	go func() {
		<-kc.stopCh
		kc.workQueue.ShutDown()
	}()

	go func() {
		kc.waitGroup.Add(1)
		defer kc.waitGroup.Done()
		for {
			item, quit := kc.workQueue.Get()
			if quit {
				return
			}
			kc.Log().Debugf("worker: begin processing %v", item)
			kc.Log().Infoln("Processing queue")
			for namespace := range kc.kubeNamespaces {
				kc.Log().Println(namespace)
			}

			//kc.Reconfigure()
			kc.Log().Debugf("worker: done processing %v", item)
			kc.workQueue.Done(item)
		}
	}()
}
