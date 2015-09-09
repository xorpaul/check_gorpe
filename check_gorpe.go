package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	netUrl "net/url"
	"os"
	"strconv"
	"strings"
)

var debug bool

// Debugf is a helper function for debug logging if mainCfgSection["debug"] is set
func Debugf(s string) {
	if debug {
		log.Print("DEBUG " + s)
	}
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	var (
		hostFlag  = flag.String("H", "", "Hostname to query")
		portFlag  = flag.Int("p", 5666, "Port to send the query to, defaults to 5666")
		cmdFlag   = flag.String("c", "", "gorpe Command to execute on the remote host")
		debugFlag = flag.Bool("debug", false, "log debug output, defaults to false")
		argFlag   = flag.String("a", "", "Optional gorpe command argument")
		//argFlag = flag.Values([]string, []string{}, "Optional gorpe command argument")
		// tls flags
		certFile = flag.String("cert", "", "A PEM eoncoded certificate file.")
		keyFile  = flag.String("key", "", "A PEM encoded private key file.")
		caFile   = flag.String("ca", "", "A PEM eoncoded CA's certificate file.")
	)

	//var argsFlag []string
	//flag.Var(&argsFlag, "a", "Optional gorpe command arguments")

	flag.Parse()

	if t := os.Getenv("VIMRUNTIME"); len(t) > 0 {
		*debugFlag = true
		*hostFlag = "itinfra-mon-bs100.server.lan"
		*portFlag = 5668
		*cmdFlag = "check_http_wild"
		*argFlag = "-H puppet-hosting-ca.server.lan -S -p 8140 -e 404 -t 1"
	}

	if *hostFlag == "" {
		log.Println("Hostname parameter -H is mandatory!")
		os.Exit(1)
	}

	debug = *debugFlag

	// TLS stuff
	tlsConfig := &tls.Config{}
	//Use only modern ciphers
	tlsConfig.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	//Use only TLS v1.2
	tlsConfig.MinVersion = tls.VersionTLS12

	//Don't allow session resumption
	tlsConfig.SessionTicketsDisabled = true

	tlsConfig.InsecureSkipVerify = true

	// initialize http client with defaults
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	var certFilenames = map[string]string{
		"cert": *certFile,
		"key":  *keyFile,
		"ca":   *caFile,
	}

	client_cert_enabled := false
	for _, filename := range certFilenames {
		if filename != "" {
			if _, err := os.Stat(filename); os.IsNotExist(err) {
				// generate certs
				log.Println("Certificate file: " + filename + " not found! Exiting...\n")
				os.Exit(1)
			} else {
				Debugf("Certificate file: " + filename + " found.\n")
				client_cert_enabled = true
			}
		}
	}

	if client_cert_enabled {
		mycert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			panic(err)
		}

		tlsConfig.Certificates = make([]tls.Certificate, 1)
		tlsConfig.Certificates[0] = mycert

		if *caFile != "" {
			pem, err := ioutil.ReadFile(*caFile)
			if err != nil {
				panic(err)
			}

			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(pem) {
				panic("Failed appending certs")
			} else {
				Debugf("Successfully loaded CA file: " + *caFile)
			}
			tlsConfig.RootCAs = certPool
			tlsConfig.ClientCAs = certPool

		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.BuildNameToCertificate()

		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client = &http.Client{Transport: transport}

	} //Close if client_cert_enabled

	url := "https://" + *hostFlag + ":" + strconv.Itoa(*portFlag)

	if *cmdFlag != "" {
		url += "/" + *cmdFlag
	}

	var out []byte
	if *argFlag != "" {
		var resp *http.Response
		v := netUrl.Values{}

		argCounter := 1
		v.Set("arg"+string(argCounter), *argFlag)
		argCounter++

		Debugf("Trying to POST " + url)
		resp, err := client.PostForm(url, v)
		if err != nil {
			log.Println(err)
			os.Exit(3)
		}
		out, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			os.Exit(3)
		}
		defer resp.Body.Close()
	} else {
		var resp *http.Response
		Debugf("Trying to GET" + url)
		resp, err := client.Get(url)
		if err != nil {
			log.Println(err)
			os.Exit(3)
		}
		out, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			os.Exit(3)
		}
		defer resp.Body.Close()
	}

	outArray := strings.Split(string(out), "\n")
	Debugf("outArray:" + strings.Join(outArray, " "))
	Debugf("len(outArray):" + string(len(outArray)))

	returnCodeLine := outArray[len(outArray)-2]
	Debugf("returnCodeLine:" + returnCodeLine)
	outArray = outArray[:len(outArray)-2]

	returnCode := returnCodeLine[len(returnCodeLine)-1:]
	Debugf("returnCode:" + returnCode)

	exitCode, _ := strconv.Atoi(returnCode)
	Debugf("exitCode:" + string(exitCode))

	log.Print(strings.Join(outArray, "\n"))
	//log.Print(strconv.Atoi(returnCode))
	os.Exit(exitCode)

}
