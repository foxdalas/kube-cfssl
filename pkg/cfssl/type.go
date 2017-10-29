package cfssl

import (
	"github.com/foxdalas/cfssl-kube/pkg/cfkube_const"
	"github.com/sirupsen/logrus"
)

type Cfssl struct {
	cfkube.Cfssl

	log *logrus.Entry

	cfkube cfkube.CFKube

	notFound string
}

type AuthRequest struct {
	Token   string `json:"token"`
	Request string `json:"request"`
}

type Request struct {
	CertificateRequest interface{} `json:"certificate_request"`
	Hosts              []string    `json:"hosts"`
	Profile            string      `json:"profile"`
	Subject            struct {
		Names []struct {
			C  string `json:"C"`
			L  string `json:"L"`
			O  string `json:"O"`
			OU string `json:"OU"`
		} `json:"names"`
	} `json:"subject"`
}

type Response struct {
	Success bool `json:"success"`
	Result  struct {
		Certificate string `json:"certificate"`
	} `json:"result"`
	Errors   []interface{} `json:"errors"`
	Messages []interface{} `json:"messages"`
}

type InfoResponse struct {
	Success bool `json:"success"`
	Result  struct {
		Certificate string   `json:"certificate"`
		Usages      []string `json:"usages"`
		Expiry      string   `json:"expiry"`
	} `json:"result"`
	Errors   []interface{} `json:"errors"`
	Messages []interface{} `json:"messages"`
}
