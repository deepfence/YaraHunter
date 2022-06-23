package output

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	// "strings"
	"github.com/deepfence/IOCScanner/core"
	"github.com/fatih/color"
)

const (
	Indent = "  " // Indentation for Json printing
)

type IOCFound struct {
	LayerID               string  `json:"Image Layer ID,omitempty"`
	RuleID                int     `json:"Matched Rule ID,omitempty"`
	RuleName              string  `json:"Matched Rule Name,omitempty"`
	PartToMatch           string  `json:"Matched Part,omitempty"`
	Match                 string  `json:"String to Match,omitempty"`
	Regex                 string  `json:"Signature to Match,omitempty"`
	Severity              string  `json:"Severity,omitempty"`
	SeverityScore         float64 `json:"Severity Score,omitempty"`
	PrintBufferStartIndex int     `json:"Starting Index of Match in Original Content,omitempty"`
	MatchFromByte         int     `json:"Relative Starting Index of Match in Displayed Substring"`
	MatchToByte           int     `json:"Relative Ending Index of Match in Displayed Substring"`
	CompleteFilename      string  `json:"Full File Name,omitempty"`
	MatchedContents       string  `json:"Matched Contents,omitempty"`
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

func (dirOutput *JsonDirIOCOutput) SetDirName(dirName string) {
	dirOutput.DirName = dirName
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

	// fmt.Println(string(file))

	return nil
}

func (imageOutput JsonImageIOCOutput) PrintJsonHeader() {
	fmt.Printf("{\n")
	fmt.Printf(Indent+"\"Timestamp\": \"%s\",\n", time.Now().Format("2006-01-02 15:04:05.000000000 -07:00"))
	fmt.Printf(Indent+"\"Image Name\": \"%s\",\n", imageOutput.ImageName)
	fmt.Printf(Indent+"\"Image ID\": \"%s\",\n", imageOutput.ImageId)
	fmt.Printf(Indent + "\"IOC\": [\n")
}

func (imageOutput JsonImageIOCOutput) PrintJsonFooter() {
	printJsonFooter()
}

func (dirOutput JsonDirIOCOutput) PrintJsonHeader() {
	fmt.Printf("{\n")
	fmt.Printf(Indent+"\"Timestamp\": \"%s\",\n", time.Now().Format("2006-01-02 15:04:05.000000000 -07:00"))
	fmt.Printf(Indent+"\"Directory Name\": \"%s\",\n", dirOutput.DirName)
	fmt.Printf(Indent + "\"IOC\": [\n")
}

func (dirOutput JsonDirIOCOutput) PrintJsonFooter() {
	printJsonFooter()
}

func printJsonFooter() {
	fmt.Printf("\n" + Indent + "]\n")
	fmt.Printf("}\n")
}

func PrintColoredIOC(IOC []IOCFound, isFirstIOC *bool) {
	for _, IOC := range IOC {
		printColoredIOCJsonObject(IOC, isFirstIOC)
		*isFirstIOC = false
	}
}

// Function to print json object with the matches IOC string in color
// @parameters
// IOC - Structure with details of the IOC found
// isFirstIOC - indicates if some IOC are already printed, used to properly format json
func printColoredIOCJsonObject(IOC IOCFound, isFirstIOC *bool) {
	Indent3 := Indent + Indent + Indent

	if *isFirstIOC {
		fmt.Printf(Indent + Indent + "{\n")
	} else {
		fmt.Printf(",\n" + Indent + Indent + "{\n")
	}

	fmt.Printf(Indent3+"\"Image Layer ID\": %s,\n", jsonMarshal(IOC.LayerID))
	fmt.Printf(Indent3+"\"Matched Rule ID\": %d,\n", IOC.RuleID)
	fmt.Printf(Indent3+"\"Matched Rule Name\": %s,\n", jsonMarshal(IOC.RuleName))
	fmt.Printf(Indent3+"\"Matched Part\": %s,\n", jsonMarshal(IOC.PartToMatch))
	fmt.Printf(Indent3+"\"String to Match\": %s,\n", jsonMarshal(IOC.Match))
	fmt.Printf(Indent3+"\"Signature to Match\": %s,\n", jsonMarshal(IOC.Regex))
	fmt.Printf(Indent3+"\"Severity\": %s,\n", jsonMarshal(IOC.Severity))
	fmt.Printf(Indent3+"\"Severity Score\": %.2f,\n", IOC.SeverityScore)
	fmt.Printf(Indent3+"\"Starting Index of Match in Original Content\": %d,\n", IOC.PrintBufferStartIndex)
	fmt.Printf(Indent3+"\"Relative Starting Index of Match in Displayed Substring\": %d,\n", IOC.MatchFromByte)
	fmt.Printf(Indent3+"\"Relative Ending Index of Match in Displayed Substring\": %d,\n", IOC.MatchToByte)
	fmt.Printf(Indent3+"\"Full File Name\": %s,\n", jsonMarshal(IOC.CompleteFilename))
	match := IOC.MatchedContents
	from := IOC.MatchFromByte
	to := IOC.MatchToByte
	prefix := removeFirstLastChar(jsonMarshal(match[0:from]))
	coloredMatch := color.RedString(removeFirstLastChar(jsonMarshal(string(match[from:to]))))
	suffix := removeFirstLastChar(jsonMarshal(match[to:]))
	fmt.Printf(Indent3+"\"Matched Contents\": \"%s%s%s\"\n", prefix, coloredMatch, suffix)

	fmt.Printf(Indent + Indent + "}")
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

func IOCToIOCInfos(out []IOCFound) []*pb.IOCInfo {
	res := make([]*pb.IOCInfo, 0)
	for _, v := range out {
		res = append(res, IOCToIOCInfo(v))
	}
	return res
}

func IOCToIOCInfo(out IOCFound) *pb.IOCInfo {
	return &pb.IOCInfo{
		ImageLayerId: out.LayerID,
		Rule: &pb.MatchRule{
			Id:               int32(out.RuleID),
			Name:             out.RuleName,
			Part:             out.PartToMatch,
			StringToMatch:    out.Match,
			SignatureToMatch: out.Regex,
		},
		Match: &pb.Match{
			StartingIndex:         int64(out.PrintBufferStartIndex),
			RelativeStartingIndex: int64(out.MatchFromByte),
			RelativeEndingIndex:   int64(out.MatchToByte),
			FullFilename:          out.CompleteFilename,
			MatchedContent:        jsonMarshal(out.MatchedContents),
		},
		Severity: &pb.Severity{
			Level: out.Severity,
			Score: float32(out.SeverityScore),
		},
	}
}
