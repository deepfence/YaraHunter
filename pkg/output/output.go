package output

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/deepfence/YaraHunter/utils"
	pb "github.com/deepfence/agent-plugins-grpc/proto"
	log "github.com/sirupsen/logrus"

	// "github.com/fatih/color"
	"io/ioutil"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Indent = "  " // Indentation for Json printing
)

var (
	scanFilename       = utils.GetDfInstallDir() + "/var/log/fenced/malware-scan/malware_scan.log"
	scanStatusFilename = utils.GetDfInstallDir() + "/var/log/fenced/malware-scan-log/malware_scan_log.log"
)

type IOCFound struct {
	LayerID          string   `json:"Image Layer ID,omitempty"`
	RuleName         string   `json:"Matched Rule Name,omitempty"`
	StringsToMatch   []string `json:"Matched Part,omitempty"`
	CategoryName     []string `json:"Category,omitempty"`
	Severity         string   `json:"Severity,omitempty"`
	SeverityScore    float64  `json:"Severity Score,omitempty"`
	FileSeverity     string   `json:"FileSeverity,omitempty"`
	FileSevScore     float64  `json:"File Severity Score,omitempty"`
	CompleteFilename string   `json:"Full File Name,omitempty"`
	Meta             []string `json:"rule meta"`

	MetaRules map[string]string `json:"rule metadata"`
	Summary   string            `json:"Summary,omitempty"`
	Class     string            `json:"Class,omitempty"`
}

type IOCOutput interface {
	WriteIOC(string) error
}

type JsonDirIOCOutput struct {
	Timestamp time.Time
	DirName   string `json:"Directory Name"`
	IOC       []IOCFound
}

type JsonImageIOCOutput struct {
	Timestamp   time.Time
	ImageName   string `json:"Image Name"`
	ImageId     string `json:"Image ID"`
	ContainerId string `json:"Container ID"`
	IOC         []IOCFound
}

func (imageOutput *JsonImageIOCOutput) SetImageName(imageName string) {
	imageOutput.ImageName = imageName
}

func (imageOutput *JsonImageIOCOutput) SetImageId(imageId string) {
	imageOutput.ImageId = imageId
}

func (imageOutput *JsonImageIOCOutput) SetTime() {
	imageOutput.Timestamp = time.Now()
}

func (imageOutput *JsonImageIOCOutput) SetIOC(IOC []IOCFound) {
	imageOutput.IOC = IOC
}

func (imageOutput JsonImageIOCOutput) WriteIOC(outputFilename string) error {
	err := printIOCToJsonFile(imageOutput, outputFilename)
	return err
}

func (dirOutput *JsonDirIOCOutput) SetTime() {
	dirOutput.Timestamp = time.Now()
}

func (dirOutput *JsonDirIOCOutput) SetIOC(IOC []IOCFound) {
	dirOutput.IOC = IOC
}

func (dirOutput JsonDirIOCOutput) WriteIOC(outputFilename string) error {
	err := printIOCToJsonFile(dirOutput, outputFilename)
	return err
}

func printIOCToJsonFile(IOCJson interface{}, outputFilename string) error {
	file, err := json.MarshalIndent(IOCJson, "", Indent)
	if err != nil {
		log.Errorf("printIOCToJsonFile: Couldn't format json output: %s", err)
		return err
	}
	err = ioutil.WriteFile(outputFilename, file, os.ModePerm)
	if err != nil {
		log.Errorf("printIOCToJsonFile: Couldn't write json output to file: %s", err)
		return err
	}

	return nil
}

func MalwaresToMalwareInfos(out []IOCFound) []*pb.MalwareInfo {
	res := make([]*pb.MalwareInfo, 0)
	// log.Error("reached everywhere here", out)
	for _, v := range out {
		// log.Error("did it reach to this point 1", v)
		if MalwaresToMalwareInfo(v) != nil {
			res = append(res, MalwaresToMalwareInfo(v))
		}
		//log.Error("did it reach to this point", v)
	}
	return res
}

func MalwaresToMalwareInfo(out IOCFound) *pb.MalwareInfo {
	bool := true
	if !(utf8.ValidString(out.LayerID) && utf8.ValidString(out.RuleName) && utf8.ValidString(out.Summary) && utf8.ValidString(out.Class) &&
		utf8.ValidString(out.FileSeverity) && utf8.ValidString(out.CompleteFilename)) {
		bool = false
	}
	meta := make([]string, 0)
	metaRules := make(map[string]string)
	stringsToMatch := make([]string, 0)
	for i := range out.Meta {
		if !utf8.ValidString(out.Meta[i]) && bool {
			log.Debugf("reached the meta point %s : %t", out.Meta[i], utf8.ValidString(out.Meta[i]))
		} else {
			meta = append(meta, out.Meta[i])
		}
	}
	out.Meta = meta

	for k, v := range out.MetaRules {
		if !utf8.ValidString(v) && bool {
			log.Debugf("reached the meta point %s : %t", v, utf8.ValidString(v))
		} else {
			metaRules[k] = v
		}
	}
	out.MetaRules = metaRules

	for i := range out.StringsToMatch {
		if !utf8.ValidString(out.StringsToMatch[i]) && bool {
			log.Debugf("reached the meta point %s : %t", out.StringsToMatch[i], utf8.ValidString(out.StringsToMatch[i]))
		} else {
			stringsToMatch = append(stringsToMatch, out.StringsToMatch[i])
		}
	}
	out.StringsToMatch = stringsToMatch

	if bool {
		return &pb.MalwareInfo{
			ImageLayerId:     out.LayerID,
			RuleName:         out.RuleName,
			StringsToMatch:   out.StringsToMatch,
			SeverityScore:    out.SeverityScore,
			FileSeverity:     out.FileSeverity,
			FileSevScore:     out.FileSevScore,
			CompleteFilename: out.CompleteFilename,
			Meta:             out.Meta,
			MetaRules:        out.MetaRules,
			Summary:          out.Summary,
			Class:            out.Class,
		}
	} else {
		return nil
	}
}

func (imageOutput JsonImageIOCOutput) PrintJsonHeader() {
	fmt.Fprintf(os.Stdout, "{\n")
	fmt.Fprintf(os.Stdout, Indent+"\"Timestamp\": \"%s\",\n", time.Now().Format("2006-01-02 15:04:05.000000000 -07:00"))
	fmt.Fprintf(os.Stdout, Indent+"\"Image Name\": \"%s\",\n", imageOutput.ImageName)
	fmt.Fprintf(os.Stdout, Indent+"\"Image ID\": \"%s\",\n", imageOutput.ImageId)
	fmt.Fprintf(os.Stdout, Indent+"\"Malware match detected are\": [\n")
}

func (imageOutput JsonImageIOCOutput) PrintJsonFooter() {
	printJsonFooter()
}

func (dirOutput JsonDirIOCOutput) PrintJsonHeader() {
	fmt.Fprintf(os.Stdout, "{\n")
	fmt.Fprintf(os.Stdout, Indent+"\"Timestamp\": \"%s\",\n", time.Now().Format("2006-01-02 15:04:05.000000000 -07:00"))
	fmt.Fprintf(os.Stdout, Indent+"\"Directory Name\": \"%s\",\n", dirOutput.DirName)
	fmt.Fprintf(os.Stdout, Indent+"\"Malware match detected are\": [\n")
}

func (dirOutput JsonDirIOCOutput) PrintJsonFooter() {
	printJsonFooter()
}

func printJsonFooter() {
	fmt.Fprintf(os.Stdout, "\n"+Indent+"]\n")
	fmt.Fprintf(os.Stdout, "}\n")
}

func PrintColoredIOC(IOCs []IOCFound, isFirstIOC *bool) {
	for _, IOC := range IOCs {
		printColoredIOCJsonObject(IOC, isFirstIOC, IOC.FileSevScore, IOC.FileSeverity)
		*isFirstIOC = false
	}
}

// Function to print json object with the matches IOC string in color
// @parameters
// IOC - Structure with details of the IOC found
// isFirstIOC - indicates if some IOC are already printed, used to properly format json
func printColoredIOCJsonObject(IOC IOCFound, isFirstIOC *bool, fileScore float64, severity string) {
	Indent3 := Indent + Indent + Indent

	if *isFirstIOC {
		fmt.Fprintf(os.Stdout, Indent+Indent+"{\n")
	} else {
		fmt.Fprintf(os.Stdout, ",\n"+Indent+Indent+"{\n")
	}

	if IOC.LayerID != "" {
		fmt.Fprintf(os.Stdout, Indent3+"\"Image Layer ID\": %s,\n", jsonMarshal(IOC.LayerID))
	}
	fmt.Fprintf(os.Stdout, Indent3+"\"Matched Rule Name\": %s,\n", jsonMarshal(IOC.RuleName))
	fmt.Fprintf(os.Stdout, Indent3+"\"Strings to match are\": [\n")
	var count = 0
	for _, c := range IOC.StringsToMatch {
		if len(c) > 0 {
			if count == 0 {
				fmt.Fprintf(os.Stdout, Indent3+Indent3+jsonMarshal(c)+"\n")
			} else {
				fmt.Fprintf(os.Stdout, Indent3+Indent3+","+jsonMarshal(c)+"\n")
			}

			count++
		}
	}
	fmt.Fprintf(os.Stdout, Indent3+"],\n")
	summary := ""
	class := "Undefined"
	categoryName := "["
	for i, c := range IOC.CategoryName {
		if len(c) > 0 {
			str := []string{"The file", IOC.CompleteFilename, "has a", c, "match."}
			summary = strings.Join(str, " ")
			categoryName = categoryName + jsonMarshal(c)
			if i == 0 && len(IOC.CategoryName) > 1 {
				categoryName = categoryName + ","
			}
		}
	}
	categoryName = categoryName + "]"

	//fmt.Fprintf(os.Stdout, Indent3+"\"String to Match\": %s,\n", IOC.StringsToMatch)
	//fmt.Fprintf(os.Stdout, Indent3+"\"File Match Severity\": %s,\n", jsonMarshal(severity))
	//fmt.Fprintf(os.Stdout, Indent3+"\"File Match Severity Score\": %.2f,\n", fileScore)
	fmt.Fprintf(os.Stdout, Indent3+"\"Category\": %s,\n", categoryName)
	fmt.Fprintf(os.Stdout, Indent3+"\"File Name\": %s,\n", jsonMarshal(IOC.CompleteFilename))
	for _, c := range IOC.Meta {
		var metaSplit = strings.Split(c, " : ")
		if len(metaSplit) > 1 {
			fmt.Fprintf(os.Stdout, Indent3+jsonMarshal(metaSplit[0])+":"+jsonMarshal(strings.Replace(metaSplit[1], "\n", "", -1))+",\n")
			if metaSplit[0] == "description" {
				str := []string{"The file has a rule match that ", strings.Replace(metaSplit[1], "\n", "", -1) + "."}
				summary = summary + strings.Join(str, " ")
			} else {
				if metaSplit[0] == "info" {
					class = strings.TrimSpace(strings.Replace(metaSplit[1], "\n", "", -1))
				} else {
					if len(metaSplit[0]) > 0 {
						str := []string{"The matched rule file's ", metaSplit[0], " is", strings.Replace(metaSplit[1], "\n", "", -1) + "."}
						summary = summary + strings.Join(str, " ")
					}
				}

			}
		}
	}
	fmt.Fprintf(os.Stdout, Indent3+"\"Summary\": %s\n", jsonMarshal(summary))

	fmt.Fprintf(os.Stdout, Indent3+"\"Class\": %s\n", class)

	fmt.Fprintf(os.Stdout, Indent+Indent+"}\n")
}

func jsonMarshal(input string) string {
	output, _ := json.Marshal(input)
	return string(output)
}

func removeFirstLastChar(input string) string {
	if len(input) <= 1 {
		return input
	}
	return input[1 : len(input)-1]
}

func writeToFile(malwareScanMsg string, filename string) error {
	os.MkdirAll(filepath.Dir(filename), 0755)

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	malwareScanMsg = strings.Replace(malwareScanMsg, "\n", " ", -1)
	if _, err = f.WriteString(malwareScanMsg + "\n"); err != nil {
		return err
	}
	return nil
}

func WriteScanStatus(status, scan_id, scan_message string) {
	var scanLogDoc = make(map[string]interface{})
	scanLogDoc["scan_id"] = scan_id
	scanLogDoc["scan_status"] = status
	scanLogDoc["scan_message"] = scan_message

	byteJson, err := json.Marshal(scanLogDoc)
	if err != nil {
		log.Errorf("Error marshalling json for malware-logs-status: %s", err)
		return
	}

	err = writeToFile(string(byteJson), scanStatusFilename)
	if err != nil {
		log.Errorf("Error in sending data to malware-logs-status to mark in progress: %s", err)
		return
	}
}

type MalwareScanDoc struct {
	IOCFound
	ScanID    string `json:"scan_id,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

func WriteScanData(malwares []IOCFound, scan_id string) {
	for _, malware := range malwares {
		doc := MalwareScanDoc{
			IOCFound:  malware,
			ScanID:    scan_id,
			Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z",
		}
		byteJson, err := json.Marshal(doc)
		if err != nil {
			log.Errorf("Error marshalling json: %s", err)
			continue
		}
		err = writeToFile(string(byteJson), scanFilename)
		if err != nil {
			log.Errorf("Error in writing data to malware scan file: %s", err)
		}
	}
}
