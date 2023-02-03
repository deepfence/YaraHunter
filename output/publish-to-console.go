package output

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	MgmtConsoleUrl string
	DeepfenceKey   string
)

func init() {
	MgmtConsoleUrl = os.Getenv("MGMT_CONSOLE_URL")
	mgmtConsolePort := os.Getenv("MGMT_CONSOLE_PORT")
	if mgmtConsolePort != "" && mgmtConsolePort != "443" {
		MgmtConsoleUrl += ":" + mgmtConsolePort
	}
	DeepfenceKey = os.Getenv("DEEPFENCE_KEY")
}

func IngestMalwareScanResults(malwareScanMsg string, index string) error {
	malwareScanMsg = strings.Replace(malwareScanMsg, "\n", " ", -1)
	postReader := bytes.NewReader([]byte(malwareScanMsg))
	retryCount := 0
	httpClient, err := buildClient()
	if err != nil {
		return err
	}
	for {
		httpReq, err := http.NewRequest("POST", "https://"+MgmtConsoleUrl+"/ingest/topics/"+index, postReader)
		if err != nil {
			return err
		}
		httpReq.Close = true
		httpReq.Header.Add("deepfence-key", DeepfenceKey)
		httpReq.Header.Add("Content-Type", "application/vnd.kafka.json.v2+json")
		resp, err := httpClient.Do(httpReq)
		if err != nil {
			return err
		}
		if resp.StatusCode == 200 {
			resp.Body.Close()
			break
		} else {
			if retryCount > 5 {
				errMsg := fmt.Sprintf("Unable to complete request. Got %d ", resp.StatusCode)
				resp.Body.Close()
				return errors.New(errMsg)
			}
			resp.Body.Close()
			retryCount += 1
			time.Sleep(5 * time.Second)
		}
	}
	return nil
}

func buildClient() (*http.Client, error) {
	// Set up our own certificate pool
	tlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 1024,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Minute,
				KeepAlive: 15 * time.Minute,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
		},
		Timeout: 15 * time.Minute,
	}
	return client, nil
}
