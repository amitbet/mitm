package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/amitbet/mitm"
)

var (
	hostname, _ = os.Hostname()

	dir      = path.Join(os.Getenv("HOME"), ".mitm")
	keyFile  = path.Join(dir, "ca-key.pem")
	certFile = path.Join(dir, "ca-cert.pem")
)

func main() {
	ca, err := loadCA()
	if err != nil {
		log.Fatal("problem in loadCA: ", err)
	}
	p := &mitm.Proxy{
		CA: &ca,
		TLSServerConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			//CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		},
		Wrap: cloudToButt,
	}
	log.Fatal("problem in http listener: ", http.ListenAndServe(":8088", p))
}

func loadCA() (cert tls.Certificate, err error) {
	// TODO(kr): check file permissions
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if os.IsNotExist(err) {
		cert, err = genCA()
	}
	if err == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	}
	return
}

func genCA() (cert tls.Certificate, err error) {
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return
	}
	certPEM, keyPEM, err := GenCA(hostname)
	if err != nil {
		return
	}
	cert, _ = tls.X509KeyPair(certPEM, keyPEM)
	err = ioutil.WriteFile(certFile, certPEM, 0400)
	if err == nil {
		err = ioutil.WriteFile(keyFile, keyPEM, 0400)
	}
	return cert, err
}

type cloudToButtResponse struct {
	http.ResponseWriter

	sub         bool
	wroteHeader bool
}

func (w *cloudToButtResponse) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	ctype := w.Header().Get("Content-Type")
	if strings.HasPrefix(ctype, "text/html") {
		w.sub = true
	}
	w.ResponseWriter.WriteHeader(code)
}

var (
	cloud = []byte("the cloud")
	butt  = []byte("my   butt")
)

func (w *cloudToButtResponse) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(200)
	}
	if w.sub {
		p = bytes.Replace(p, cloud, butt, -1)
	}
	return w.ResponseWriter.Write(p)
}

func cloudToButt(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Accept-Encoding", "")
		upstream.ServeHTTP(&cloudToButtResponse{ResponseWriter: w}, r)
	})
}

//------------------------------------

const (
	caMaxAge   = 5 * 365 * 24 * time.Hour
	leafMaxAge = 24 * time.Hour
	caUsage    = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	leafUsage = caUsage
)

func genKeyPair() (*ecdsa.PrivateKey, error) {
	seed := elliptic.P521()
	reader := rand.Reader
	return ecdsa.GenerateKey(seed, reader)
}

func GenCA(name string) (certPEM, keyPEM []byte, err error) {
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(caMaxAge),
		KeyUsage:              caUsage,
		BasicConstraintsValid: true,
		IsCA:               true,
		MaxPathLen:         2,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	key, err := genKeyPair()
	if err != nil {
		return
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}

	// err = ioutil.WriteFile("./ca.cer", keyDER, 0644)
	// if err != nil {
	// 	log.Fatal("can't write cer file!")
	// }

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: keyDER,
	})
	return
}
