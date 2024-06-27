package scan

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"fmt"

	"github.com/gabriel-vasile/mimetype"

	// yaraConf "github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/hillu/go-yara/v4"
	yr "github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
)

var (
	ErrmaxMalwaresExceeded = errors.New("number of secrets exceeded max-secrets")
	execMimeTypes          = []string{"text/x-shellscript", "application/x-executable", "application/x-mach-binary", "application/x-msdownload", "application/exe", "application/x-msdos-program", "application/x-elf", "application/x-sharedlib", "application/x-pie-executable", "application/java-archive", "application/x-java-archive", "text/x-python", "application/x-batch"}
	sharedMimeTypesList    = []string{"application/x-sharedlib"}
)

// Data type to store details about the container image after parsing manifest
type manifestItem struct {
	Config   string
	RepoTags []string
	Layers   []string
	LayerIds []string `json:",omitempty"`
}

type fileMatches struct {
	fileName        string
	iocs            []output.IOCFound
	updatedScore    float64
	updatedSeverity string
}

var (
	imageTarFileName = "save-output.tar"
)

func calculateSeverity(inputString []string, severity string, severityScore float64) (string, float64) {
	updatedSeverity := "low"
	lenMatch := len(inputString)
	MinIOCLength := 3

	MaxIOCLength := 6

	if lenMatch < MinIOCLength {
		return severity, severityScore
	}

	if lenMatch >= MaxIOCLength {
		return "high", 10.0
	}

	scoreRange := 10.0 - severityScore

	increment := ((float64(lenMatch) - float64(MinIOCLength)) * scoreRange) / (float64(MaxIOCLength) - float64(MinIOCLength))

	updatedScore := severityScore + increment
	if updatedScore > 10.0 {
		updatedScore = 10.0
	}

	if 2.5 < updatedScore && updatedScore <= 7.5 {
		updatedSeverity = "medium"
	} else if 7.5 < updatedScore {
		updatedSeverity = "high"
	}

	return updatedSeverity, math.Round(updatedScore*100) / 100
}

func isSharedLibrary(filePath string) bool {
	mtype, err := mimetype.DetectFile(filePath)
	if err != nil {
		logrus.Errorf("Error: %v", err)
		return false
	}
	for _, execType := range sharedMimeTypesList {
		if mtype.String() == execType {
			return true
		}
	}
	return false
}

func fileMimetypeCheck(filePath string, mimeTypesList []string) bool {
	mtype, err := mimetype.DetectFile(filePath)
	if err != nil {
		logrus.Errorf("Error: %v", err)
		return false
	}

	for _, execType := range mimeTypesList {
		if strings.Contains(mtype.String(), execType) {
			return true
		}
	}

	return false
}

func isExecutable(path string) bool {
	// todo: add more checks later
	return fileMimetypeCheck(path, execMimeTypes)
}

func BytesToString(b []byte) (s string) {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

type Iterator struct {
	blocksize int
	rs        io.ReadSeeker
	offset    int64
	length    int
}

func (s *Iterator) read(buf []byte) {
	s.rs.Seek(s.offset, io.SeekStart)
	s.rs.Read(buf)
}

func (s *Iterator) First() *yara.MemoryBlock {
	s.offset = 0
	return &yara.MemoryBlock{
		Base:      uint64(s.offset),
		Size:      uint64(s.length),
		FetchData: s.read,
	}
}

func (s *Iterator) Next() *yara.MemoryBlock {
	s.offset += int64(s.length)
	end, _ := s.rs.Seek(0, io.SeekEnd)
	s.length = int(end - s.offset)
	if s.length <= 0 {
		return nil
	}
	if s.length > s.blocksize {
		s.length = s.blocksize
	}
	return &yara.MemoryBlock{
		Base:      uint64(s.offset),
		Size:      uint64(s.length),
		FetchData: s.read,
	}
}

func ScanFile(s *Scanner, fileName string, f io.ReadSeeker, fsize int, iocs *[]output.IOCFound, layer string) error {
	logrus.Debugf("Scanning file %s", fileName)
	var (
		matches yr.MatchRules
		err     error
	)

	type ruleVariable struct {
		name  string
		value interface{}
	}

	variables := []ruleVariable{
		{"filename", filepath.ToSlash(filepath.Base(fileName))},
		{"filepath", filepath.ToSlash(fileName)},
		{"extension", filepath.Ext(fileName)},
	}

	yrScanner := s.YaraScanner
	yrScanner.SetCallback(&matches)
	for _, v := range variables {
		if v.value != nil {
			if err = yrScanner.DefineVariable(v.name, v.value); err != nil {
				return err
			}
		}
	}

	hostMountPath := *s.HostMountPath
	if hostMountPath != "" {
		fileName = strings.TrimPrefix(fileName, hostMountPath)
	}

	it := Iterator{blocksize: 1*1024*1024, rs: f}
	err = yrScanner.ScanMemBlocks(&it)
	if err != nil {
		return err
	}

	var iocsFound []output.IOCFound
	totalMatchesStringData := make([]string, 0)
	for _, m := range matches {
		for _, str := range m.Strings {
			totalMatchesStringData = append(totalMatchesStringData, BytesToString(str.Data))
		}

		slices.Sort(totalMatchesStringData)
		matchesStringDataSlice := slices.Compact(totalMatchesStringData)

		matchesMetaData := make([]string, len(m.Metas))
		for _, strMeta := range m.Metas {
			matchesMetaData = append(matchesMetaData, fmt.Sprintf("%v : %v \n", strMeta.Identifier, strMeta.Value))
		}

		iocsFound = append(iocsFound, output.IOCFound{
			RuleName:         m.Rule,
			CategoryName:     m.Tags,
			StringsToMatch:   matchesStringDataSlice,
			Meta:             matchesMetaData,
			CompleteFilename: fileName,
		})
	}
	var fileMat fileMatches
	fileMat.fileName = fileName
	fileMat.iocs = iocsFound
	updatedSeverity, updatedScore := calculateSeverity(totalMatchesStringData, "low", 0)
	fileMat.updatedSeverity = updatedSeverity
	fileMat.updatedScore = updatedScore
	// var isFirstIOC bool = true
	if len(matches) > 0 {
		// output.PrintColoredIOC(tempIOCsFound, &isFirstIOC, fileMat.updatedScore, fileMat.updatedSeverity)
		for _, m := range iocsFound {
			m.FileSeverity = updatedSeverity
			m.FileSevScore = updatedScore
			StringsMatch := make([]string, 0)
			for _, c := range m.StringsToMatch {
				if len(c) > 0 {
					StringsMatch = append(StringsMatch, c)
				}
			}
			m.StringsToMatch = StringsMatch
			m.LayerID = layer
			summary := ""
			class := "Undefined"
			m.MetaRules = make(map[string]string)
			for _, c := range m.Meta {
				var metaSplit = strings.Split(c, " : ")
				if len(metaSplit) > 1 {

					// fmt.Fprintf(os.Stdout, Indent3+jsonMarshal(metaSplit[0])+":"+jsonMarshal(strings.Replace(metaSplit[1], "\n", "", -1))+",\n")
					m.MetaRules[metaSplit[0]] = strings.ReplaceAll(metaSplit[1], "\n", "")
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
			m.Summary = summary
			m.Class = class
			// *(*(*iocs)) = append(*(*(*iocs)), m)
			*iocs = append(*iocs, m)
		}
	}
	return err
}

const (
	outputChannelSize = 100
)

// Execute the specified command and return the output
// @parameters
// name - Command to be executed
// args - all the arguments to be passed to the command
// @returns
// string - contents of standard output
// string - contents of standard error
// int - exit code of the executed command
func runCommand(name string, args ...string) (stdout string, stderr string, exitCode int) {
	var defaultFailedCode = 1
	var outbuf, errbuf bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf

	err := cmd.Run()
	stdout = outbuf.String()
	stderr = errbuf.String()

	if err != nil {
		// try to get the exit code
		if exitError, ok := err.(*exec.ExitError); ok {
			ws := exitError.Sys().(syscall.WaitStatus)
			exitCode = ws.ExitStatus()
		} else {
			// This will happen (in OSX) if `name` is not available in $PATH,
			// in this situation, exit code could not be get, and stderr will be
			// empty string very likely, so we use the default fail code, and format err
			// to string and set to stderr
			logrus.Debugf("Could not get exit code for failed program: %v, %v", name, args)
			exitCode = defaultFailedCode
			if stderr == "" {
				stderr = err.Error()
			}
		}
	} else {
		// success, exitCode should be 0 if go is ok
		ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
		exitCode = ws.ExitStatus()
	}
	return
}

type ImageExtractionResult struct {
	IOCs    []output.IOCFound
	ImageID string
}
