package cfssl

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/foxdalas/kube-cfssl/pkg/kubecfssl_const"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
	"github.com/ghodss/yaml"
)

func New(kubecfssl kubecfssl.KubeCfssl) *Cfssl {
	c := &Cfssl{
		kubecfssl: kubecfssl,
		certificateData: make(map[string][]byte),
	}

	if kubecfssl != nil {
		c.log = c.kubecfssl.Log().WithField("context", "cfssl")
		c.notFound = fmt.Sprintf("kube-cfssl (version %s) - 404 not found", kubecfssl.Version())
	} else {
		c.log = logrus.WithField("context", "cfssl")
	}
	return c
}

func (c *Cfssl) getBundle() {
	c.certificateData[kubecfssl.BundleCertificateName] = []byte(string(string(c.certificateData[kubecfssl.CertificateName]) +
		string(c.certificateData[kubecfssl.RootCertificateName]) + "\n" +
			string(c.certificateData[kubecfssl.CertificateKeyName])))
}

func (c *Cfssl) GetCertificate(pkiURL string, authKey string, csrConfig string) map[string][]byte {
	c.createKey()
	c.getCRT(c.certificateRequest(pkiURL, authKey,csrConfig))
	c.getCA(pkiURL, "info")
	c.getBundle()
	return c.certificateData
}


func (c *Cfssl) certificateRequest (pkiURL string, authKey string,csrConfig string) *http.Response {
	request := []byte(c.constructAuthRequest(authKey, c.getCSRConfig(csrConfig)))
	url := pkiURL + "/api/v1/cfssl/authsign"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(request))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	c.checkError(err)

	return resp
}

func (c *Cfssl) getCSRConfig(file string) []byte {
	csrConfigByte, err := ioutil.ReadFile(file)
	if err != nil {
		c.Log().Fatalf("Cant't read CSR Config file %s", file)
	}

	var csrJson Request
	yaml.Unmarshal(csrConfigByte, &csrJson)

	csr := c.createCSR(string(c.certificateData[kubecfssl.CertificateKeyName]))
	csrJson.CertificateRequest = string(csr)
	byteRequest, _ := json.Marshal(csrJson)
	return []byte(byteRequest)
}

func (c *Cfssl) Log() (log *logrus.Entry) {
	return c.log
}

func (c *Cfssl) createKey() {
	key, err := rsa.GenerateKey(rand.Reader, kubecfssl.RsaKeySize)
	c.checkError(err)

	priv_der := x509.MarshalPKCS1PrivateKey(key)

	priv_blk := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   priv_der,
	}

	priv_pem := pem.EncodeToMemory(&priv_blk)
	c.certificateData["crt.key"] = priv_pem
}

func (c *Cfssl) getCA(pkiURL string, method string) []byte {
	var infoResponse InfoResponse
	var jsonStr = []byte(`{"profile": "peer"}`)
	req, err := http.NewRequest("POST", pkiURL+kubecfssl.PKIUri+method, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	c.checkError(err)

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal([]byte(body), &infoResponse)
	c.certificateData[kubecfssl.RootCertificateName] = []byte(infoResponse.Result.Certificate)

	return []byte(infoResponse.Result.Certificate)
}

func (c *Cfssl) createCSR(keyPlain string) []byte {
	keyByte := []byte(keyPlain)

	block, _ := pem.Decode(keyByte)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	c.checkError(err)

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	c.checkError(err)
	csr := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBytes,
	})
	return csr
}

func (c *Cfssl) constructAuthRequest(key string, request []byte) string {
	reqData := AuthRequest{c.ComputeHmac256(request, key), base64.StdEncoding.EncodeToString(request)}
	reqJson, _ := json.Marshal(reqData)
	jsonStr := string(reqJson)
	c.Log().Infoln("Processing certificate request")
	c.Log().Debugln("JSON Request: ", string(jsonStr))
	return jsonStr
}

func (c *Cfssl) ComputeHmac256(message []byte, secret string) string {
	b, _ := hex.DecodeString(secret)
	h := hmac.New(sha256.New, []byte(b))
	h.Write(message)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (c *Cfssl) getCRT(resp *http.Response) []byte {

	if resp.StatusCode  == 200 {
		body, _ := ioutil.ReadAll(resp.Body)

		var response Response
		json.Unmarshal([]byte(body), &response)
		c.Log().Infoln("Certificate generation complete")
		c.certificateData[kubecfssl.CertificateName] = []byte(response.Result.Certificate)
		return []byte(response.Result.Certificate)
	} else {
		c.Log().Errorln("Response: ", resp.StatusCode)
		return []byte("123")
	}
}

func (c *Cfssl) checkError(err error) {
	if err != nil {
		c.log.Fatalln("Fatal error ", err.Error())
		os.Exit(1)
	}
}