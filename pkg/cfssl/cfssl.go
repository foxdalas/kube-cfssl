package cfssl

import (
	"cfssl-kube/pkg/cfkube_const"
	"github.com/sirupsen/logrus"
	"fmt"
	"encoding/hex"
	"encoding/base64"
	"encoding/json"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/rand"
	"os"
	"encoding/pem"
	"io/ioutil"
	"crypto/x509"
	"net/http"
	"bytes"
)

func New(cfKube cfkube.CFKube) *Cfssl {
	c := &Cfssl{
		cfkube: cfKube,
	}

	if cfKube != nil {
		c.log = c.cfkube.Log().WithField("context", "cfssl")
		c.notFound = fmt.Sprintf("cfkube (version %s) - 404 not found", cfKube.Version())
	} else {
		c.log = logrus.WithField("context", "cfssl")
	}
	return c
}

func getBundle(cert []byte, ca []byte, key []byte) []byte {
	bundle := string(cert) + string(ca) + "\n" + string(key)
	return []byte(bundle)
}

func (c *Cfssl) GetCertificate(pkiURL string, authKey string, csrConfig []byte, privateKey []byte ) (map[string][]byte) {

	data := make(map[string][]byte)
	data["crt.key"] = privateKey

	var csrJson Request
	json.Unmarshal(csrConfig, &csrJson)
	csr :=  c.createCSR(string(data["crt.key"]))
	csrJson.CertificateRequest = string(csr)
	byteRequest, _ := json.Marshal(csrJson)
	jsonByte := []byte(byteRequest)

	request := []byte(c.constructAuthRequest(authKey, jsonByte))
	url := pkiURL + "/api/v1/cfssl/authsign"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(request))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	c.checkError(err)

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	cert := c.getCRT(resp.StatusCode, string(body))
	ca := c.getCA(pkiURL,"info")
	bundle := getBundle(cert, ca, privateKey)

	data["crt.pem"] = cert
	data["ca.pem"] = ca
	data["bundle.pem"] = bundle

	return data
}

func (c *Cfssl) Log() (log *logrus.Entry) {
	return c.log
}

func (c *Cfssl) CreateKey() []byte {
	key, err := rsa.GenerateKey(rand.Reader, cfkube.RsaKeySize)
	c.checkError(err)

	priv_der := x509.MarshalPKCS1PrivateKey(key);

	priv_blk := pem.Block {
		Type: "RSA PRIVATE KEY",
		Headers: nil,
		Bytes: priv_der,
	}

	priv_pem := pem.EncodeToMemory(&priv_blk);

	return priv_pem
}

func (c *Cfssl) getCA(pkiURL string, method string) []byte {
	var infoResponse InfoResponse
	var jsonStr = []byte(`{"profile": "peer"}`)
	req, err := http.NewRequest("POST", pkiURL + cfkube.PKIUri + method, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	c.checkError(err)

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal([]byte(body), &infoResponse)

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
	reqData := AuthRequest {c.ComputeHmac256(request, key),base64.StdEncoding.EncodeToString(request)}
	reqJson, _ := json.Marshal(reqData)
	jsonStr := string(reqJson)
	c.Log().Infoln("Processing certificate request")
	c.Log().Debugln("JSON Request: ", string(jsonStr))
	return jsonStr
}

func (c *Cfssl) ComputeHmac256(message []byte, secret string) string{
	b, _ := hex.DecodeString(secret)
	h := hmac.New(sha256.New, []byte(b))
	h.Write(message)
	//return string(h.Sum(nil))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (c *Cfssl) getCRT(responseCode int, responseBody string) ([]byte) {
	certificate := []byte(nil)

	if responseCode == 200 {
		var response Response
		json.Unmarshal([]byte(responseBody), &response)
		c.Log().Infoln("Certificate generation complete")
		certificate = []byte(response.Result.Certificate)
	} else {
		c.Log().Errorln("Response: ", responseCode)
	}
	return certificate

}

func (c *Cfssl) checkError(err error) {
	if err != nil {
		c.log.Fatalln("Fatal error ", err.Error())
		os.Exit(1)
	}
}

