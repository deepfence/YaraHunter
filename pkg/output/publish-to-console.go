package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	dsc "github.com/deepfence/golang_deepfence_sdk/client"
	oahttp "github.com/deepfence/golang_deepfence_sdk/utils/http"
	log "github.com/sirupsen/logrus"
)

var (
	MgmtConsoleURL string
	DeepfenceKey   string
)

func init() {
	MgmtConsoleURL = os.Getenv("MGMT_CONSOLE_URL")
	mgmtConsolePort := os.Getenv("MGMT_CONSOLE_PORT")
	if mgmtConsolePort != "" && mgmtConsolePort != "443" {
		MgmtConsoleURL += ":" + mgmtConsolePort
	}
	DeepfenceKey = os.Getenv("DEEPFENCE_KEY")
}

func IngestMalwareScanResults(malwareScanMsg string, index string) error {
	malwareScanMsg = strings.ReplaceAll(malwareScanMsg, "\n", " ")
	postReader := bytes.NewReader([]byte(malwareScanMsg))
	retryCount := 0
	httpClient, err := buildClient()
	if err != nil {
		fmt.Println("Error building http client " + err.Error())
		return err
	}
	for {
		httpReq, err := http.NewRequest("POST", "https://"+MgmtConsoleURL+"/df-api/ingest?doc_type="+index, postReader)
		if err != nil {
			return err
		}
		httpReq.Close = true
		httpReq.Header.Add("deepfence-key", DeepfenceKey)
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

type Publisher struct {
	client         *oahttp.OpenapiHttpClient
	stopScanStatus chan bool
}

func GetHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

func NewPublisher(url string, port string, key string) (*Publisher, error) {
	client := oahttp.NewHttpsConsoleClient(url, port)
	if err := client.APITokenAuthenticate(key); err != nil {
		return nil, err
	}
	return &Publisher{client: client}, nil
}

func (p *Publisher) SendReport(hostname, imageName, containerID, nodeType string) {

	report := dsc.IngestersReportIngestionData{}

	host := map[string]interface{}{
		"node_id":               hostname,
		"host_name":             hostname,
		"node_name":             hostname,
		"node_type":             "host",
		"cloud_region":          "cli",
		"cloud_provider":        "cli",
		"kubernetes_cluster_id": "",
	}
	report.HostBatch = []map[string]interface{}{host}

	if nodeType != "" {
		image := map[string]interface{}{
			"docker_image_name_with_tag": imageName,
			"docker_image_id":            imageName,
			"node_id":                    imageName,
			"node_name":                  imageName,
			"node_type":                  nodeType,
		}
		s := strings.Split(imageName, ":")
		if len(s) == 2 {
			image["docker_image_name"] = s[0]
			image["docker_image_tag"] = s[1]
		}
		containerImageEdge := map[string]interface{}{
			"source":       hostname,
			"destinations": imageName,
		}
		report.ContainerImageBatch = []map[string]interface{}{image}
		report.ContainerImageEdgeBatch = []map[string]interface{}{containerImageEdge}
	}

	log.Debugf("report: %+v", report)

	req := p.client.Client().TopologyAPI.IngestSyncAgentReport(context.Background())
	req = req.IngestersReportIngestionData(report)

	resp, err := p.client.Client().TopologyAPI.IngestSyncAgentReportExecute(req)
	if err != nil {
		log.Error(err)
	}
	log.Debugf("report response %s", resp.Status)
}

func (p *Publisher) StartScan(nodeID, nodeType string) string {

	scanTrigger := dsc.ModelMalwareScanTriggerReq{
		Filters: *dsc.NewModelScanFilterWithDefaults(),
		NodeIds: []dsc.ModelNodeIdentifier{},
	}

	nodeIds := dsc.ModelNodeIdentifier{NodeId: nodeID, NodeType: nodeType}
	if nodeType != "" {
		nodeIds.NodeType = "host"
	}

	scanTrigger.NodeIds = append(scanTrigger.NodeIds, nodeIds)

	req := p.client.Client().MalwareScanAPI.StartMalwareScan(context.Background())
	req = req.ModelMalwareScanTriggerReq(scanTrigger)
	res, resp, err := p.client.Client().MalwareScanAPI.StartMalwareScanExecute(req)
	if err != nil {
		log.Error(err)
		return ""
	}

	log.Debugf("start scan response: %+v", res)
	log.Debugf("start scan response status: %s", resp.Status)

	return res.GetScanIds()[0]
}

func (p *Publisher) PublishScanStatusMessage(scanID, message, status string) {
	data := dsc.IngestersMalwareScanStatus{}
	data.SetScanId(scanID)
	data.SetScanStatus(status)
	data.SetScanMessage(message)

	req := p.client.Client().MalwareScanAPI.IngestMalwareScanStatus(context.Background())
	req = req.IngestersMalwareScanStatus([]dsc.IngestersMalwareScanStatus{data})

	resp, err := p.client.Client().MalwareScanAPI.IngestMalwareScanStatusExecute(req)
	if err != nil {
		log.Error(err)
	}

	log.Debugf("publish scan status response: %v", resp)
}

func (p *Publisher) PublishScanError(scanID, errMsg string) {
	p.PublishScanStatusMessage(scanID, errMsg, "ERROR")
}

func (p *Publisher) PublishScanStatusPeriodic(scanID, status string) {
	go func() {
		p.PublishScanStatusMessage(scanID, "", status)
		ticker := time.NewTicker(30 * time.Second)
		for {
			select {
			case <-ticker.C:
				p.PublishScanStatusMessage(scanID, "", status)
			case <-p.stopScanStatus:
				return
			}
		}
	}()
}

func (p *Publisher) StopPublishScanStatus() {
	p.stopScanStatus <- true
	time.Sleep(5 * time.Second)
}

func (p *Publisher) IngestSecretScanResults(scanID string, malwares []IOCFound) error {
	data := []dsc.IngestersMalware{}

	for _, malware := range malwares {
		mr := dsc.NewIngestersMetaRules()
		mr.SetAuthor(malware.MetaRules["author"])
		mr.SetDate(malware.MetaRules["date"])
		mr.SetDescription(malware.MetaRules["description"])
		mr.SetFileSeverity(malware.FileSeverity)
		mr.SetFiletype(malware.MetaRules["filetype"])
		mr.SetInfo(malware.MetaRules["info"])
		mr.SetReference(malware.MetaRules["reference"])
		mr.SetRuleId(malware.MetaRules["rule_id"])
		mr.SetRuleName(malware.MetaRules["rule_name"])
		mr.SetVersion(malware.MetaRules["version"])

		m := dsc.NewIngestersMalware()
		m.SetScanId(scanID)
		m.SetTimestamp(time.Now())
		m.SetClass(malware.Class)
		m.SetRuleName(malware.RuleName)
		m.SetStringsToMatch(malware.StringsToMatch)
		m.SetSeverityScore(int32(malware.SeverityScore))
		m.SetFileSevScore(float32(malware.FileSevScore))
		m.SetFileSeverity(malware.FileSeverity)
		m.SetCompleteFilename(malware.CompleteFilename)
		m.SetImageLayerId(malware.LayerID)
		m.SetSummary(malware.Summary)
		m.SetMeta(malware.Meta)
		m.SetMetaRules(*mr)

		data = append(data, *m)
	}

	req := p.client.Client().MalwareScanAPI.IngestMalware(context.Background())
	req = req.IngestersMalware(data)

	resp, err := p.client.Client().MalwareScanAPI.IngestMalwareExecute(req)
	if err != nil {
		log.Error(err)
	}

	log.Debugf("publish scan results response: %v", resp)

	return nil
}
