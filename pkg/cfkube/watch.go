package cfkube

import (
	"k8s.io/client-go/util/workqueue"
)

func (cf *CFKube) WatchReconfigure() {

	cf.workQueue = workqueue.New()

	// handle worker shutdown
	go func() {
		<-cf.stopCh
		cf.workQueue.ShutDown()
	}()

	go func() {
		cf.waitGroup.Add(1)
		defer cf.waitGroup.Done()
		for {
			item, quit := cf.workQueue.Get()
			if quit {
				return
			}
			cf.Log().Debugf("worker: begin processing %v", item)
			cf.Log().Infoln("Processing queue")
			for namespace := range cf.cfKubeNamespaces {
				cf.Log().Println(namespace)
			}

			//cf.Reconfigure()
			cf.Log().Debugf("worker: done processing %v", item)
			cf.workQueue.Done(item)
		}
	}()
}
