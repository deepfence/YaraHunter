package output

import (
	"encoding/json"
	"fmt"
	"github.com/deepfence/YaRadare/core"
	pb "github.com/deepfence/agent-plugins-grpc/proto"
	// "github.com/fatih/color"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

const (
	Indent = "  " // Indentation for Json printing
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
		core.GetSession().Log.Error("printIOCToJsonFile: Couldn't format json output: %s", err)
		return err
	}
	err = ioutil.WriteFile(outputFilename, file, os.ModePerm)
	if err != nil {
		core.GetSession().Log.Error("printIOCToJsonFile: Couldn't write json output to file: %s", err)
		return err
	}

	return nil
}

func MalwaresToMalwareInfos(out []IOCFound) []*pb.MalwareInfo {
	res := make([]*pb.MalwareInfo, 0)
	core.GetSession().Log.Error("reached everywhere here", out)
	for _, v := range out {
		//core.GetSession().Log.Error("reached here 2", v)
		res = append(res, MalwaresToMalwareInfo(v))
	}
	return res
}

func MalwaresToMalwareInfo(out IOCFound) *pb.MalwareInfo {
	core.GetSession().Log.Error("reached malware here 2 %v", out)
	core.GetSession().Log.Error("test pb here %s", &pb.MalwareInfo{
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
	})
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
	class := ""
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
					class = metaSplit[1]
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
