package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strconv"

	"github.com/Jeffail/tunny"
	"github.com/deepfence/YaraHunter/core"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
	log "github.com/sirupsen/logrus"
)

const (
	scanStatusComplete       = "COMPLETE"
	scanStatusError          = "ERROR"
	defaultScanConcurrency   = 5
	malwareScanIndexName     = "malware-scan"
	malwareScanLogsIndexName = "malware-scan-logs"
)

var (
	scanConcurrency    int
	httpScanWorkerPool *tunny.Pool
)

type standaloneRequest struct {
	ImageNameWithTag string `json:"image_name_with_tag"`
}

type imageParameters struct {
	scanner *scan.Scanner
	scanId  string
	form    url.Values
}

func init() {
	var err error
	scanConcurrency, err = strconv.Atoi(os.Getenv("MALWARE_SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrency = defaultScanConcurrency
	}
	httpScanWorkerPool = tunny.NewFunc(scanConcurrency, processImageWrapper)
}

func runMalwareScan(writer http.ResponseWriter, request *http.Request) {
	log.Info("entered into scan here")
	if err := request.ParseForm(); err != nil {
		fmt.Fprintf(writer, "ParseForm() err: %v", err)
		return
	} else if request.PostForm.Get("image_name_with_tag_list") == "" {
		http.Error(writer, "{\"error\":\"Image Name with tag list is required \"}", http.StatusConflict)
	} else {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		fmt.Fprintf(writer, "{\"status\": \"Scan Queued\"}")
		go processScans(request.PostForm)
	}
}

// runMalwareScanStandalone is used to run malware scan on image and publish the result in stdout
// this doesnot publish the result to any http endpoint, ex: mgmt console
func runMalwareScanStandalone(writer http.ResponseWriter, request *http.Request) {
	fmt.Printf("rbody: %s\n", request.Body)
	requestDump, err := httputil.DumpRequest(request, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))

	b, err := ioutil.ReadAll(request.Body)
	defer request.Body.Close()
	if err != nil {
		http.Error(writer, err.Error(), 500)
		return
	}

	// decoder := json.NewDecoder(request.Body)
	var req standaloneRequest
	// err = decoder.Decode(&req)
	scanner := &scan.Scanner{}
	*scanner.ConfigPath = "/home/deepfence/usr/config.yaml"
	*scanner.RulesPath = "/home/deepfence/usr/yara_rules"
	*scanner.ImageName = req.ImageNameWithTag

	err = json.Unmarshal(b, &req)
	if err != nil {
		fmt.Fprintf(writer, "Parse err: %v", err)
		return
	}

	fmt.Printf("Malware scan Scan triggered for %s: ", req.ImageNameWithTag)
	res, err := scanner.ExtractAndScanImage(req.ImageNameWithTag)
	if err != nil {
		fmt.Fprintf(writer, "Image scan err: %v", err)
		return
	}

	JsonImageIOCOutput := output.JsonImageIOCOutput{ImageName: req.ImageNameWithTag}
	JsonImageIOCOutput.SetTime()
	JsonImageIOCOutput.SetImageId(res.ImageId)
	JsonImageIOCOutput.SetIOC(res.IOCs)

	outByte, err := json.Marshal(JsonImageIOCOutput)
	if err != nil {
		fmt.Fprintf(writer, "report marshaling error: %v", err)
		return
	}

	fmt.Fprintf(writer, string(outByte))
	return

}

func processScans(form url.Values) {
	scanner := &scan.Scanner{}
	if form.Get("config_path") == "" {
		*scanner.ConfigPath = "/home/deepfence/usr/config.yaml"
	}
	if form.Get("rules_path") == "" {
		*scanner.RulesPath = "/home/deepfence/usr/yara_rules"
	}

	imageNameList := form["image_name_with_tag_list"]
	for index, imageName := range imageNameList {
		*scanner.ImageName = imageName
		go httpScanWorkerPool.Process(imageParameters{scanner: scanner, scanId: form["scan_id_list"][index], form: form})
	}
}

func processImageWrapper(imageParamsInterface interface{}) interface{} {
	imageParams, ok := imageParamsInterface.(imageParameters)
	if !ok {
		fmt.Println("Error reading input from API")
		return nil
	}
	processImage(imageParams.scanner, imageParams.scanId, imageParams.form)
	return nil
}

func processImage(scanner *scan.Scanner, scanId string, form url.Values) {
	tempFolder, err := core.GetTmpDir(*scanner.ImageName, *scanner.TempDirectory)
	if err != nil {
		fmt.Println("error creating temp dirs:" + err.Error())
		return
	}
	imageSaveCommand := exec.Command("python3", "/home/deepfence/usr/registry_image_save.py", "--image_name_with_tag", *scanner.ImageName, "--registry_type", form.Get("registry_type"),
		"--mgmt_console_url", output.MgmtConsoleUrl, "--deepfence_key", output.DeepfenceKey, "--credential_id", form.Get("credential_id"),
		"--output_folder", tempFolder)
	_, err = runCommand(imageSaveCommand, "Image Save:"+*scanner.ImageName)
	if err != nil {
		fmt.Println("error saving image:" + err.Error())
		return
	}
	scanAndPublish(scanner, scanId, tempFolder, form)
}

func scanAndPublish(scanner *scan.Scanner, scanId string, tempDir string, postForm url.Values) {
	var malwareScanLogDoc = make(map[string]interface{})
	malwareScanLogDoc["scan_status"] = "IN_PROGRESS"
	malwareScanLogDoc["node_id"] = *scanner.ImageName
	malwareScanLogDoc["node_name"] = *scanner.ImageName
	malwareScanLogDoc["time_stamp"] = core.GetTimestamp()
	malwareScanLogDoc["@timestamp"] = core.GetCurrentTime()
	malwareScanLogDoc["scan_id"] = scanId
	for key, value := range postForm {
		if len(value) > 0 {
			malwareScanLogDoc[key] = value[0]
		}
	}
	malwareScanLogDoc["image_name_with_tag_list"] = nil
	malwareScanLogDoc["scan_id_list"] = nil
	byteJson, err := json.Marshal(malwareScanLogDoc)
	if err != nil {
		fmt.Println("Error in marshalling malware in_progress log object to json:" + err.Error())
	} else {
		err = output.IngestMalwareScanResults(string(byteJson), malwareScanLogsIndexName)
		if err != nil {
			fmt.Println("Error in updating in_progress log" + err.Error())
		}
	}
	fmt.Println("extracting scans")
	res, err := scanner.ExtractAndScanFromTar(tempDir)
	if err != nil {
		malwareScanLogDoc["scan_status"] = "ERROR"
		byteJson, err := json.Marshal(malwareScanLogDoc)
		if err != nil {
			fmt.Println("Error in marshalling malware result object to json:" + err.Error())
			return
		}
		err = output.IngestMalwareScanResults(string(byteJson), malwareScanLogsIndexName)
		if err != nil {
			fmt.Println("error ingesting data: " + err.Error())
		}
		return
	}
	timestamp := core.GetTimestamp()
	currTime := core.GetCurrentTime()
	malwares := output.MalwaresToMalwareInfos(res.IOCs)
	for _, malware := range malwares {
		var malwareScanDoc = make(map[string]interface{})
		for key, value := range postForm {
			if len(value) > 0 {
				malwareScanDoc[key] = value[0]
			}
		}
		malwareScanDoc["image_name_with_tag_list"] = nil
		malwareScanDoc["scan_id_list"] = nil
		malwareScanDoc["time_stamp"] = timestamp
		malwareScanDoc["@timestamp"] = currTime
		malwareScanDoc["node_id"] = *scanner.ImageName
		malwareScanDoc["node_name"] = *scanner.ImageName
		malwareScanDoc["scan_id"] = scanId
		values := reflect.ValueOf(*malware)
		typeOfS := values.Type()
		for index := 0; index < values.NumField(); index++ {
			if values.Field(index).CanInterface() {
				malwareScanDoc[typeOfS.Field(index).Name] = values.Field(index).Interface()
			}
		}
		byteJson, err := json.Marshal(malwareScanDoc)
		if err != nil {
			fmt.Println("Error in marshalling malware result object to json:" + err.Error())
			return
		}
		err = output.IngestMalwareScanResults(string(byteJson), malwareScanIndexName)
		if err != nil {
			fmt.Println("Error in sending data to malwareScanIndex:" + err.Error())
		}
	}
	if err == nil {
		malwareScanLogDoc["scan_status"] = scanStatusComplete
	} else {
		malwareScanLogDoc["scan_status"] = scanStatusError
		malwareScanLogDoc["scan_message"] = err.Error()
	}
	malwareScanLogDoc["time_stamp"] = timestamp
	malwareScanLogDoc["@timestamp"] = currTime
	byteJson, err = json.Marshal(malwareScanLogDoc)
	if err != nil {
		fmt.Println("Error in marshalling malwareScanLogDoc to json:" + err.Error())
		return
	}
	err = output.IngestMalwareScanResults(string(byteJson), malwareScanLogsIndexName)
	if err != nil {
		fmt.Println("Error in sending data to malwareScanLogsIndex:" + err.Error())
	}
}

func RunHttpServer(listenPort string) error {
	http.Handle("/malware-scan", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		log.Info("Entered scan")
		runMalwareScan(writer, request)
	}))
	http.HandleFunc("/malware-scan/test", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "Hello World!")
	})
	log.Info("Http Server listening before ")
	http.ListenAndServe(":"+listenPort, nil)
	log.Info("Http Server listening on " + listenPort)
	return nil
}

func RunStandaloneHttpServer(listenPort string) error {
	fmt.Println("Trying to start Http Server on " + listenPort)
	http.Handle("/malware-scan", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		log.Info("Entered scan")
		runMalwareScanStandalone(writer, request)
	}))
	http.HandleFunc("/malware-scan/ping", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "pong")
	})
	http.ListenAndServe(":"+listenPort, nil)
	log.Info("Http Server listening on " + listenPort)
	return nil
}

// operation is prepended to error message in case of error: optional
func runCommand(cmd *exec.Cmd, operation string) (*bytes.Buffer, error) {
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	errorOnRun := cmd.Run()
	if errorOnRun != nil {
		return nil, errors.New(operation + fmt.Sprint(errorOnRun) + ": " + stderr.String())
	}
	return &out, nil
}
