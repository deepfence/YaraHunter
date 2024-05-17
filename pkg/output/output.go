package output

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/deepfence/YaraHunter/utils"
	pb "github.com/khulnasoft-lab/agent-plugins-grpc/srcgo"
	log "github.com/sirupsen/logrus"

	// "github.com/fatih/color"

	"os"
	"strings"
	"time"
	"unicode/utf8"

	tw "github.com/olekukonko/tablewriter"
)

const (
	Indent = "  " // Indentation for Json printing
)

// severity
const (
	HIGH   = "high"
	MEDIUM = "medium"
	LOW    = "low"
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

type JSONDirIOCOutput struct {
	Timestamp time.Time
	DirName   string `json:"Directory Name"`
	IOC       []IOCFound
}

type JSONImageIOCOutput struct {
	Timestamp   time.Time
	ImageName   string `json:"Image Name"`
	ImageID     string `json:"Image ID"`
	ContainerID string `json:"Container ID"`
	IOC         []IOCFound
}

func (imageOutput *JSONImageIOCOutput) SetImageName(imageName string) {
	imageOutput.ImageName = imageName
}

func (imageOutput *JSONImageIOCOutput) SetImageID(imageID string) {
	imageOutput.ImageID = imageID
}

func (imageOutput *JSONImageIOCOutput) SetTime() {
	imageOutput.Timestamp = time.Now()
}

func (imageOutput *JSONImageIOCOutput) SetIOC(ioc []IOCFound) {
	imageOutput.IOC = ioc
}

func (imageOutput *JSONImageIOCOutput) GetIOC() []IOCFound {
	return imageOutput.IOC
}

func (imageOutput JSONImageIOCOutput) WriteJSON() error {
	return printIOCToJSON(imageOutput)
}

func (imageOutput JSONImageIOCOutput) WriteTable() error {
	return WriteTableOutput(&imageOutput.IOC)
}

func (dirOutput *JSONDirIOCOutput) SetTime() {
	dirOutput.Timestamp = time.Now()
}

func (dirOutput *JSONDirIOCOutput) SetIOC(ioc []IOCFound) {
	dirOutput.IOC = ioc
}

func (dirOutput *JSONDirIOCOutput) GetIOC() []IOCFound {
	return dirOutput.IOC
}

func (dirOutput JSONDirIOCOutput) WriteJSON() error {
	return printIOCToJSON(dirOutput)
}

func (dirOutput JSONDirIOCOutput) WriteTable() error {
	return WriteTableOutput(&dirOutput.IOC)
}

func printIOCToJSON(iocJSON interface{}) error {
	file, err := json.MarshalIndent(iocJSON, "", Indent)
	if err != nil {
		log.Errorf("printIOCToJsonFile: Couldn't format json output: %s", err)
		return err
	}

	fmt.Println(string(file))

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
		// log.Error("did it reach to this point", v)
	}
	return res
}

func MalwaresToMalwareInfo(out IOCFound) *pb.MalwareInfo {
	bool := true
	if !(utf8.ValidString(out.LayerID) && utf8.ValidString(out.RuleName) &&
		utf8.ValidString(out.Summary) && utf8.ValidString(out.Class) &&
		utf8.ValidString(out.FileSeverity) && utf8.ValidString(out.CompleteFilename)) {
		bool = false
	}
	meta := make([]string, 0)
	metaRules := make(map[string]string)
	stringsToMatch := make([]string, 0)
	for i := range out.Meta {
		if !utf8.ValidString(out.Meta[i]) && bool {
			log.Debugf("reached the meta point %s : %t", out.Meta[i], utf8.ValidString(out.Meta[i]))
		} else if len(out.Meta[i]) > 0 {
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

func PrintColoredIOC(iocs []IOCFound, isFirstIOC *bool) {
	for _, IOC := range iocs {
		printColoredIOCJsonObject(IOC, isFirstIOC, IOC.FileSevScore, IOC.FileSeverity)
		*isFirstIOC = false
	}
}

// Function to print json object with the matches IOC string in color
// @parameters
// IOC - Structure with details of the IOC found
// isFirstIOC - indicates if some IOC are already printed, used to properly format json
func printColoredIOCJsonObject(ioc IOCFound, isFirstIOC *bool, fileScore float64, severity string) {
	Indent3 := Indent + Indent + Indent

	if *isFirstIOC {
		fmt.Fprintf(os.Stdout, Indent+Indent+"{\n")
	} else {
		fmt.Fprintf(os.Stdout, ",\n"+Indent+Indent+"{\n")
	}

	if ioc.LayerID != "" {
		fmt.Fprintf(os.Stdout, Indent3+"\"Image Layer ID\": %s,\n", jsonMarshal(ioc.LayerID))
	}
	fmt.Fprintf(os.Stdout, Indent3+"\"Matched Rule Name\": %s,\n", jsonMarshal(ioc.RuleName))
	fmt.Fprintf(os.Stdout, Indent3+"\"Strings to match are\": [\n")
	var count = 0
	for _, c := range ioc.StringsToMatch {
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
	for i, c := range ioc.CategoryName {
		if len(c) > 0 {
			str := []string{"The file", ioc.CompleteFilename, "has a", c, "match."}
			summary = strings.Join(str, " ")
			categoryName += jsonMarshal(c)
			if i == 0 && len(ioc.CategoryName) > 1 {
				categoryName += ","
			}
		}
	}
	categoryName += "]"

	// fmt.Fprintf(os.Stdout, Indent3+"\"String to Match\": %s,\n", IOC.StringsToMatch)
	// fmt.Fprintf(os.Stdout, Indent3+"\"File Match Severity\": %s,\n", jsonMarshal(severity))
	// fmt.Fprintf(os.Stdout, Indent3+"\"File Match Severity Score\": %.2f,\n", fileScore)
	fmt.Fprintf(os.Stdout, Indent3+"\"Category\": %s,\n", categoryName)
	fmt.Fprintf(os.Stdout, Indent3+"\"File Name\": %s,\n", jsonMarshal(ioc.CompleteFilename))
	for _, c := range ioc.Meta {
		var metaSplit = strings.Split(c, " : ")
		if len(metaSplit) > 1 {
			fmt.Fprintf(os.Stdout, Indent3+jsonMarshal(metaSplit[0])+":"+jsonMarshal(strings.ReplaceAll(metaSplit[1], "\n", ""))+",\n")
			if metaSplit[0] == "description" {
				str := []string{"The file has a rule match that ", strings.ReplaceAll(metaSplit[1], "\n", "") + "."}
				summary += strings.Join(str, " ")
			} else {
				if metaSplit[0] == "info" {
					class = strings.TrimSpace(strings.ReplaceAll(metaSplit[1], "\n", ""))
				} else if len(metaSplit[0]) > 0 {
					str := []string{"The matched rule file's ", metaSplit[0], " is", strings.ReplaceAll(metaSplit[1], "\n", "") + "."}
					summary += strings.Join(str, " ")
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

func writeToFile(malwareScanMsg string, filename string) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("os.MkdirAll: %w", err)
	}

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	malwareScanMsg = strings.ReplaceAll(malwareScanMsg, "\n", " ")
	if _, err = f.WriteString(malwareScanMsg + "\n"); err != nil {
		return err
	}
	return nil
}

func WriteScanStatus(status, scanID, scanMessage string) {
	var scanLogDoc = make(map[string]interface{})
	scanLogDoc["scan_id"] = scanID
	scanLogDoc["scan_status"] = status
	scanLogDoc["scan_message"] = scanMessage

	byteJSON, err := json.Marshal(scanLogDoc)
	if err != nil {
		log.Errorf("Error marshalling json for malware-logs-status: %s", err)
		return
	}

	err = writeToFile(string(byteJSON), scanStatusFilename)
	if err != nil {
		log.Errorf("Error in sending data to malware-logs-status to mark in progress: %s", err)
		return
	}
}

type MalwareScanDoc struct {
	*pb.MalwareInfo
	ScanID    string `json:"scan_id,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

func WriteScanData(malwares []*pb.MalwareInfo, scanID string) {
	for _, malware := range malwares {
		doc := MalwareScanDoc{
			MalwareInfo: malware,
			ScanID:      scanID,
			Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z",
		}
		byteJSON, err := json.Marshal(&doc)
		if err != nil {
			log.Errorf("Error marshalling json: %s", err)
			continue
		}
		err = writeToFile(string(byteJSON), scanFilename)
		if err != nil {
			log.Errorf("Error in writing data to malware scan file: %s", err)
		}
	}
}

func WriteTableOutput(report *[]IOCFound) error {
	table := tw.NewWriter(os.Stdout)
	table.SetHeader([]string{"Rule Name", "Class", "Severity", "Matched Part", "File Name"})
	table.SetHeaderLine(true)
	table.SetBorder(true)
	table.SetAutoWrapText(true)
	table.SetAutoFormatHeaders(true)
	table.SetColMinWidth(0, 10)
	table.SetColMinWidth(1, 10)
	table.SetColMinWidth(2, 10)
	table.SetColMinWidth(3, 20)
	table.SetColMinWidth(4, 20)

	for _, r := range *report {
		table.Append([]string{r.RuleName, r.Class, r.FileSeverity, strings.Join(r.StringsToMatch, ","), r.CompleteFilename})
	}
	table.Render()
	return nil
}

type SevCount struct {
	Total  int
	High   int
	Medium int
	Low    int
}

func CountBySeverity(report []IOCFound) SevCount {
	detail := SevCount{}

	for _, r := range report {
		detail.Total += 1
		switch r.FileSeverity {
		case HIGH:
			detail.High += 1
		case MEDIUM:
			detail.Medium += 1
		case LOW:
			detail.Low += 1
		}
	}

	return detail
}

func ExitOnSeverity(severity string, count int, failOnCount int) {
	log.Debugf("ExitOnSeverity severity=%s count=%d failOnCount=%d",
		severity, count, failOnCount)
	if count >= failOnCount {
		if len(severity) > 0 {
			msg := "Exit malware scan. Number of %s malwares (%d) reached/exceeded the limit (%d).\n"
			log.Fatalf(msg, severity, count, failOnCount)
		}
		msg := "Exit malware scan. Number of malwares (%d) reached/exceeded the limit (%d).\n"
		log.Fatalf(msg, count, failOnCount)
	}
}

func FailOn(details SevCount, failOnHighCount int, failOnMediumCount int, failOnLowCount int, failOnCount int) {
	if failOnHighCount > 0 {
		ExitOnSeverity(HIGH, details.High, failOnHighCount)
	}
	if failOnMediumCount > 0 {
		ExitOnSeverity(MEDIUM, details.Medium, failOnMediumCount)
	}
	if failOnLowCount > 0 {
		ExitOnSeverity(LOW, details.Low, failOnLowCount)
	}
	if failOnCount > 0 {
		ExitOnSeverity("", details.Total, failOnCount)
	}
}
