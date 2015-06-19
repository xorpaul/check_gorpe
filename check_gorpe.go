package main

import (
	"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var debug bool

// Debugf is a helper function for debug logging if mainCfgSection["debug"] is set
func Debugf(format string, args ...interface{}) {
	if debug {
		log.Print("DEBUG "+format, args)
	}
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	var hostFlag = flag.String("H", "", "Hostname to query")
	var portFlag = flag.Int("p", 5666, "Port to send the query to, defaults to 5666")
	var cmdFlag = flag.String("c", "", "gorpe Command to execute on the remote host")
	var debugFlag = flag.Bool("debug", false, "log debug output, defaults to false")
	var argFlag = flag.String("a", "", "Optional gorpe command argument")
	//var argsFlag []string
	//flag.Var(&argsFlag, "a", "Optional gorpe command arguments")

	flag.Parse()

	if *hostFlag == "" {
		log.Println("Hostname parameter -H is mandatory!")
		os.Exit(1)
	}

	debug = *debugFlag

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// http.Get() can handle gzipped data response automagically
	url := "https://" + *hostFlag + ":" + strconv.Itoa(*portFlag)

	if *cmdFlag != "" {
		url += "/" + *cmdFlag
	}

	if *argFlag != "" {
		url += "/" + *argFlag
	}

	Debugf("Trying to GET " + url)
	resp, err := client.Get(url)

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	defer resp.Body.Close()

	out, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Println(err)
		os.Exit(3)
	}

	outArray := strings.Split(string(out), "\n")
	Debugf("outArray:", outArray)
	Debugf("len(outArray):", len(outArray))

	returnCodeLine := outArray[len(outArray)-2]
	Debugf("returnCodeLine:", returnCodeLine)
	outArray = outArray[:len(outArray)-2]

	returnCode := returnCodeLine[len(returnCodeLine)-1:]
	Debugf("returnCode:", returnCode)

	exitCode, _ := strconv.Atoi(returnCode)
	Debugf("exitCode:", exitCode)

	log.Print(strings.Join(outArray, "\n"))
	//log.Print(strconv.Atoi(returnCode))
	os.Exit(exitCode)

}
