package cacertreg

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"

	simplejson "github.com/bitly/go-simplejson"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/node"
)

type caRegister struct {
}

// fatalf formats a message to standard error and exits the program.
// The message is also printed to standard output if standard error
// is redirected to a different file.
func fatalf(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	if runtime.GOOS == "windows" {
		// The SameFile check below doesn't work on Windows.
		// stdout is unlikely to get redirected though, so just print there.
		w = os.Stdout
	} else {
		outf, _ := os.Stdout.Stat()
		errf, _ := os.Stderr.Stat()
		if outf != nil && errf != nil && os.SameFile(outf, errf) {
			w = os.Stderr
		}
	}
	fmt.Fprintf(w, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}

//CAVerify user register
func CAVerify(id string, photo string) error {
	err := userAuthOperation(id, photo)
	if err != nil {
		return err
	}
	return nil
}

func userAuthOperation(id string, photo string) error {

	err := postVerifactionData(id, photo)
	if err != nil {
		log.Error("Failed to upload user info :", "err", err)
		return err
	}
	return nil
}
func postVerifactionData(userID string, filename string) error {
	//Create form
	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)
	formFile, err := writer.CreateFormFile("uploadfile", filename)
	if err != nil {
		log.Error("Create form file failed,", "err", err)
		return err
	}

	//read file and write data to form
	//The file name may be a string separated by a semicolon
	fileArr := strings.Split(filename, ";")

	for _, v := range fileArr {
		srcFile, err := os.Open(v)
		if err != nil {
			log.Error("Open source file failed:", "err", err)
			return err
		}
		_, err = io.Copy(formFile, srcFile)

		srcFile.Close()
	}

	//add user data field
	idField, err := writer.CreateFormField("data")
	r := strings.NewReader(geneUserData(userID)) //only id and name for now
	_, err = io.Copy(idField, r)

	//add CSR field
	idHex, err := geneKeyFromID(userID)
	if err != nil {
		return err
	}
	CSR := geneCSR(idHex)
	CSRField, err := writer.CreateFormField("CSR")
	r = strings.NewReader(CSR)
	_, err = io.Copy(CSRField, r)

	writer.Close()
	contentType := writer.FormDataContentType()
	// resp, err := http.Post("http://192.168.1.26:8548/UsechainService/cert/cerauth", contentType, buf)
	resp, err := http.Post(CAurl, contentType, buf)
	fmt.Println(readerToString(resp.Body))
	if err != nil {
		log.Error("Post failed,", "err", err)
		return err
	}

	return nil
}

func geneUserData(userID string) string {
	values := map[string]string{"userID": userID}
	userData, _ := json.Marshal(values)
	return string(userData)
}

func geneCSR(idHex string) string {
	keyBytes, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("Generate RSA key pair error: %v", err)
	}
	publicKey := keyBytes.PublicKey
	savePEMKey(node.DefaultDataDir()+"/userrsa.prv", keyBytes)
	savePublicPEMKey(node.DefaultDataDir()+"/userrsa.pub", publicKey)

	subj := pkix.Name{
		CommonName: idHex,
		// Locality:   []string{idHex},
	}
	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	csrBuf := new(bytes.Buffer)
	pem.Encode(csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csrBuf.String()
}

func geneKeyFromID(ID string) (string, error) {
	if ID == "" {
		log.Error("Could not use empty string as ID")
		return "", errors.New("Could not use empty string as ID")
	}
	idHex := crypto.Keccak256Hash([]byte(ID)).Hex()
	fmt.Printf("idHex: %v\n", idHex)
	return idHex, nil
}

var CAurl = "http://usechain.cn:8548/UsechainService/cert/cerauth"
var CAquery = "http://usechain.cn:8548/UsechainService/user/cerauth"

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	log.Info("Private key saved at " + fileName)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	log.Info("Public key saved at " + fileName)
	checkError(err)
}
func readerToString(r io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	return buf.String()
}
func checkError(err error) {
	if err != nil {
		fatalf("Fatal error ", err.Error())
		// os.Exit(1)
	}
}

//VerifyQuery after user registered, user can get query info and stores ca file.
func VerifyQuery(idKey string) error {
	err := query(idKey)
	if err != nil {
		return err
	}

	return nil
}
func query(s string) error {

	err := queryID(CAquery, s)
	if err != nil {
		return err
	}
	return nil
}
func queryID(CAserver string, idKey string) error {
	u, _ := url.Parse(CAserver)
	q := u.Query()
	q.Add("idKey", idKey)
	u.RawQuery = q.Encode()
	log.Info("query url for idKey:", "idKey", idKey)
	resp, err := http.Get(u.String())
	if err != nil || resp.StatusCode != 200 {
		log.Error("Your idKey is %s, please try again later")
		if err == nil {
			log.Info("##################")
			return errors.New("response's statuscode is not 200!please try again later")
		}
		return err
		// fatalf("Your idKey is %s, please try again later", idKey)
	}

	CAbuf := new(bytes.Buffer)
	CAbuf.ReadFrom(resp.Body)
	jsondata, _ := simplejson.NewJson(CAbuf.Bytes())
	certBytes, _ := jsondata.Get("data").Get("cert").Bytes()
	if len(certBytes) == 0 {
		log.Error("Failed to download CA file \n", certBytes)
		return errors.New("Failed to download CA file")
	}
	cert := string(certBytes[:])

	userCert := node.DefaultDataDir() + "/user.crt"
	err = ioutil.WriteFile(userCert, []byte(cert), 0644)
	checkError(err)
	log.Info("CAbuf:", "CAbuf", CAbuf.String())
	log.Info("Verification successful, your CA file stored in " + userCert)

	return nil
}
