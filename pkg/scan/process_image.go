package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"fmt"

	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/core"

	// yaraConf "github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/vessel"
	yr "github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

var (
	maxMalwaresExceeded = errors.New("number of secrets exceeded max-secrets")
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

type ImageScan struct {
	imageName     string
	imageId       string
	tempDir       string
	imageManifest manifestItem
	numIOCs       uint
}

// Function to retrieve contents of container images layer by layer
// @parameters
// imageScan - Structure with details of the container image to scan
// @returns
// Error - Errors, if any. Otherwise, returns nil
func (imageScan *ImageScan) extractImage(saveImage bool) error {

	log.Infof("image scan %+v", imageScan)

	imageName := imageScan.imageName
	tempDir := imageScan.tempDir
	imageScan.numIOCs = 0

	if saveImage {
		err := imageScan.saveImageData()
		if err != nil {
			log.Errorf("image does not exist: %s", err)
			return err
		}
	}

	_, err := extractTarFile(imageName, path.Join(tempDir, imageTarFileName), tempDir)
	if err != nil {
		log.Errorf("scanImage: Could not extract image tar file: %s", err)
		return err
	}

	imageManifest, err := extractDetailsFromManifest(tempDir)
	if err != nil {
		log.Errorf("ProcessImageLayers: Could not get image's history: %s,"+
			" please specify repo:tag and check disk space \n", err.Error())
		return err
	}

	imageScan.imageManifest = imageManifest
	// reading image id from imanifest file json path and tripping off extension
	imageScan.imageId = strings.TrimSuffix(imageScan.imageManifest.Config, ".json")

	return nil
}

// Function to scan extracted layers of container images for IOCs file by file
// @parameters
// imageScan - Structure with details of the container image to scan
// @returns
// []output.IOCFound - List of all IOCs found
// Error - Errors, if any. Otherwise, returns nil
func (imageScan *ImageScan) scan(scanner *Scanner) ([]output.IOCFound, error) {
	tempDir := imageScan.tempDir
	defer core.DeleteTmpDir(tempDir)

	tempIOCsFound, err := imageScan.processImageLayers(scanner, tempDir)
	if err != nil {
		log.Errorf("scanImage: %s", err)
		return tempIOCsFound, err
	}

	return tempIOCsFound, nil
}

func (imageScan *ImageScan) scanStream(scanner *Scanner) (chan output.IOCFound, error) {
	tempDir := imageScan.tempDir
	return imageScan.processImageLayersStream(scanner, tempDir)
}

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

func ScanFilePath(s *Scanner, path string, iocs *[]output.IOCFound, layer string) (err error) {
	f, err := os.Open(path)
	if err != nil {
		log.Errorf("Error: %v", err)
		return err
	}
	defer f.Close()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		log.Errorf("Could not seek to start of file %s: %v", path, err)
		return err
	}
	if e := ScanFile(s, f, iocs, layer); err == nil && e != nil {
		err = e
	}
	return
}

func ScanFile(s *Scanner, f *os.File, iocs *[]output.IOCFound, layer string) error {
	var (
		matches yr.MatchRules
		err     error
	)

	type ruleVariable struct {
		name  string
		value interface{}
	}

	if filepath.Ext(f.Name()) != "" {
		variables := []ruleVariable{
			{"filename", filepath.ToSlash(filepath.Base(f.Name()))},
			{"filepath", filepath.ToSlash(f.Name())},
			{"extension", filepath.Ext(f.Name())},
		}

		yrScanner := s.YaraScanner
		yrScanner.SetCallback(&matches)
		for _, v := range variables {
			if v.value != nil {
				if err = yrScanner.DefineVariable(v.name, v.value); err != nil {
					return filepath.SkipDir
				}
			}
		}

		fi, err := f.Stat()
		if err != nil {
			// report.AddStringf("yara: %s: Error accessing file information, error=%s",
			// 	f.Name(), err.Error())
			return err
		}
		fileName := f.Name()
		hostMountPath := *s.HostMountPath
		if hostMountPath != "" {
			fileName = strings.TrimPrefix(fileName, hostMountPath)
		}
		if *s.MaximumFileSize > 0 && fi.Size() > *s.MaximumFileSize {
			log.Debug("\nyara: %v: Skipping large file, size=%v, max_size=%v", fileName, fi.Size(), *s.MaximumFileSize)
			return nil
		}
		err = yrScanner.ScanFileDescriptor(f.Fd())
		if err != nil {
			fmt.Println("Scan File Descriptor error, trying alternative", err)
			var buf []byte
			if buf, err = ioutil.ReadAll(f); err != nil {
				log.Errorf("yara: %s: Error reading file, error=%s",
					fileName, err.Error())
				return filepath.SkipDir
			}
			err = yrScanner.ScanMem(buf)
			if err != nil {
				fmt.Println("Scan File Mmory Error", err)
				return filepath.SkipDir
			}

		}
		var iocsFound []output.IOCFound
		totalMatchesStringData := make([]string, 0)
		for _, m := range matches {
			matchesStringData := make([]string, len(m.Strings))
			for _, str := range m.Strings {
				if !strings.Contains(strings.Join(matchesStringData, " "), string(str.Data)) {
					matchesStringData = append(matchesStringData, string(str.Data))
					totalMatchesStringData = append(totalMatchesStringData, string(str.Data))
				}
			}
			matchesMeta := make([]string, len(m.Metas))
			matchesMetaData := make([]string, len(m.Metas))
			for _, strMeta := range m.Metas {
				matchesMeta = append(matchesMeta, strMeta.Identifier)
				matchesMetaData = append(matchesMetaData, fmt.Sprintf("%v : %v \n", strMeta.Identifier, strMeta.Value))
			}

			iocsFound = append(iocsFound, output.IOCFound{
				RuleName:         m.Rule,
				CategoryName:     m.Tags,
				StringsToMatch:   matchesStringData,
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
		//var isFirstIOC bool = true
		if len(matches) > 0 {
			//output.PrintColoredIOC(tempIOCsFound, &isFirstIOC, fileMat.updatedScore, fileMat.updatedSeverity)
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

						//fmt.Fprintf(os.Stdout, Indent3+jsonMarshal(metaSplit[0])+":"+jsonMarshal(strings.Replace(metaSplit[1], "\n", "", -1))+",\n")
						m.MetaRules[metaSplit[0]] = strings.Replace(metaSplit[1], "\n", "", -1)
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
				m.Summary = summary
				m.Class = class
				// *(*(*iocs)) = append(*(*(*iocs)), m)
				*iocs = append(*iocs, m)
			}
		}

	}
	return err
}

// ScanIOCsInDir Scans a given directory recursively to find all IOCs inside any file in the dir
// @parameters
// layer - layer ID, if we are scanning directory inside container image
// baseDir - Parent directory
// fullDir - Complete path of the directory to be scanned
// isFirstIOC - indicates if some IOCs are already printed, used to properly format json
// @returns
// []output.IOCFound - List of all IOCs found
// Error - Errors if any. Otherwise, returns nil
func (s *Scanner) ScanIOCInDir(layer string, baseDir string, fullDir string, matchedRuleSet map[uint]uint, iocs *[]output.IOCFound, isContainerRunTime bool) error {
	if layer != "" {
		log.Debugf("Scan results in selected image with layer %s", layer)
	}
	if matchedRuleSet == nil {
		matchedRuleSet = make(map[uint]uint)
	}

	if layer != "" {
		core.UpdateDirsPermissionsRW(fullDir)
	}

	if *s.Options.HostMountPath != "" {
		baseDir = *s.Options.HostMountPath
	}

	ioc_count := 0
	maxFileSize := *s.Options.MaximumFileSize * 1024
	filepath.WalkDir(fullDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			fmt.Println("the error path is", err)
			log.Errorf("the error path isr ", layer)
			return nil
		}

		if entry.IsDir() {
			var scanDirPath string
			if layer != "" {
				scanDirPath = strings.TrimPrefix(path, baseDir+"/"+layer)
				if scanDirPath == "" {
					scanDirPath = "/"
				}
			} else {
				scanDirPath = path
			}
			if isContainerRunTime {
				if core.IsSkippableDir(s.Config.ExcludedContainerPaths, scanDirPath, baseDir) {
					return filepath.SkipDir
				}
			} else {
				if core.IsSkippableDir(s.Config.ExcludedPaths, scanDirPath, baseDir) {
					return filepath.SkipDir
				}
			}
			return nil

		}
		if !entry.Type().IsRegular() {
			return nil
		}

		finfo, err := entry.Info()
		if err != nil {
			logrus.Warn("Skipping %v as info could not be retrieved: %v", path, err)
			return nil
		}
		if finfo.Size() > maxFileSize || core.IsSkippableFileExtension(s.Config.ExcludedExtensions, path) {
			return nil
		}
		tmp_iocs := []output.IOCFound{}
		if err = ScanFilePath(s, path, &tmp_iocs, layer); err != nil {
			logrus.Error("Scan file failed: %v", err)
		}

		for i := range tmp_iocs {
			*iocs = append(*iocs, tmp_iocs[i])
		}
		ioc_count = len(*iocs)

		// Don't report secrets if number of secrets exceeds MAX value
		if uint(ioc_count) >= *s.Options.MaxIOC {
			return maxMalwaresExceeded
		}
		return nil
	})

	return nil
}

const (
	output_channel_size = 100
)

func (s *Scanner) ScanIOCInDirStream(layer string, baseDir string, fullDir string, matchedRuleSet map[uint]uint, isContainerRunTime bool) (chan output.IOCFound, error) {
	if layer != "" {
		log.Debugf("Scan results in selected image with layer %s", layer)
	}
	if matchedRuleSet == nil {
		matchedRuleSet = make(map[uint]uint)
	}

	if layer != "" {
		core.UpdateDirsPermissionsRW(fullDir)
	}

	if *s.Options.HostMountPath != "" {
		baseDir = *s.Options.HostMountPath
	}

	res := make(chan output.IOCFound, output_channel_size)

	go func() {
		defer close(res)
		ioc_count := 0
		maxFileSize := *s.Options.MaximumFileSize * 1024
		filepath.WalkDir(fullDir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				fmt.Println("the error path is", err)
				log.Errorf("the error path isr ", layer)
				return nil
			}

			if entry.IsDir() {
				var scanDirPath string
				if layer != "" {
					scanDirPath = strings.TrimPrefix(path, baseDir+"/"+layer)
					if scanDirPath == "" {
						scanDirPath = "/"
					}
				} else {
					scanDirPath = path
				}
				if isContainerRunTime {
					if core.IsSkippableDir(s.Config.ExcludedContainerPaths, scanDirPath, baseDir) {
						return filepath.SkipDir
					}
				} else {
					if core.IsSkippableDir(s.Config.ExcludedPaths, scanDirPath, baseDir) {
						return filepath.SkipDir
					}
				}
				return nil

			}
			if !entry.Type().IsRegular() {
				return nil
			}

			finfo, err := entry.Info()
			if err != nil {
				logrus.Warn("Skipping %v as info could not be retrieved: %v", path, err)
				return nil
			}
			if finfo.Size() > maxFileSize || core.IsSkippableFileExtension(s.Config.ExcludedExtensions, path) {
				return nil
			}
			tmp_iocs := []output.IOCFound{}
			if err = ScanFilePath(s, path, &tmp_iocs, layer); err != nil {
				logrus.Error("Scan file failed: %v", err)
			}

			for i := range tmp_iocs {
				res <- tmp_iocs[i]
			}
			ioc_count += len(tmp_iocs)

			// Don't report secrets if number of secrets exceeds MAX value
			if uint(ioc_count) >= *s.Options.MaxIOC {
				return maxMalwaresExceeded
			}
			return nil
		})
	}()

	return res, nil
}

// Extract all the layers of the container image and then find IOCs in each layer one by one
// @parameters
// imageScan - Structure with details of the container image to scan
// imageManifestPath - Complete path of directory where manifest of image has been extracted
// @returns
// []output.IOCFound - List of all IOCs found
// Error - Errors if any. Otherwise, returns nil
func (imageScan *ImageScan) processImageLayers(scanner *Scanner, imageManifestPath string) ([]output.IOCFound, error) {
	var tempIOCsFound []output.IOCFound
	var err error

	// extractPath - Base directory where all the layers should be extracted to
	extractPath := path.Join(imageManifestPath, constants.ExtractedImageFilesDir)
	layerIDs := imageScan.imageManifest.LayerIds
	layerPaths := imageScan.imageManifest.Layers
	matchedRuleSet := make(map[uint]uint)

	loopCntr := len(layerPaths)
	var IOCs []output.IOCFound
	for i := 0; i < loopCntr; i++ {
		log.Debug("Analyzing layer path: %s", layerPaths[i])
		log.Debug("Analyzing layer: %s", layerIDs[i])
		// savelayerID = layerIDs[i]
		completeLayerPath := path.Join(imageManifestPath, layerPaths[i])
		targetDir := path.Join(extractPath, layerIDs[i])
		log.Debugf("Complete layer path: %s", completeLayerPath)
		log.Debugf("Extracted to directory: %s", targetDir)
		err = core.CreateRecursiveDir(targetDir)
		if err != nil {
			log.Errorf("ProcessImageLayers: Unable to create target directory"+
				" to extract image layers... %s", err)
			return tempIOCsFound, err
		}

		_, error := extractTarFile("", completeLayerPath, targetDir)
		if error != nil {
			log.Errorf("ProcessImageLayers: Unable to extract image layer. Reason = %s", error.Error())
			// Don't stop. Print error and continue with remaining extracted files and other layers
			// return tempIOCsFound, error
		}
		log.Debug("Analyzing dir: %s", targetDir)
		err = scanner.ScanIOCInDir(layerIDs[i], extractPath, targetDir, matchedRuleSet, &IOCs, false)
		tempIOCsFound = append(tempIOCsFound, IOCs...)
		if err != nil {
			log.Errorf("ProcessImageLayers: %s", err)
			// return tempIOCsFound, err
		}

		// Don't report IOCs if number of IOCs exceeds MAX value
		if imageScan.numIOCs >= *scanner.MaxIOC {
			return tempIOCsFound, nil
		}
	}

	return tempIOCsFound, nil
}

func (imageScan *ImageScan) processImageLayersStream(scanner *Scanner, imageManifestPath string) (chan output.IOCFound, error) {
	res := make(chan output.IOCFound, output_channel_size)
	go func() {
		defer close(res)
		var err error

		// extractPath - Base directory where all the layers should be extracted to
		extractPath := path.Join(imageManifestPath, constants.ExtractedImageFilesDir)
		layerIDs := imageScan.imageManifest.LayerIds
		layerPaths := imageScan.imageManifest.Layers
		matchedRuleSet := make(map[uint]uint)

		loopCntr := len(layerPaths)
		for i := 0; i < loopCntr; i++ {
			log.Debug("Analyzing layer path: %s", layerPaths[i])
			log.Debug("Analyzing layer: %s", layerIDs[i])
			// savelayerID = layerIDs[i]
			completeLayerPath := path.Join(imageManifestPath, layerPaths[i])
			targetDir := path.Join(extractPath, layerIDs[i])
			log.Debugf("Complete layer path: %s", completeLayerPath)
			log.Debugf("Extracted to directory: %s", targetDir)
			err = core.CreateRecursiveDir(targetDir)
			if err != nil {
				log.Errorf("ProcessImageLayers: Unable to create target directory"+
					" to extract image layers... %s", err)
				continue
			}

			_, error := extractTarFile("", completeLayerPath, targetDir)
			if error != nil {
				log.Errorf("ProcessImageLayers: Unable to extract image layer. Reason = %s", error.Error())
				// Don't stop. Print error and continue with remaining extracted files and other layers
				// return tempIOCsFound, error
			}
			log.Debug("Analyzing dir: %s", targetDir)
			iocs, err := scanner.ScanIOCInDirStream(layerIDs[i], extractPath, targetDir, matchedRuleSet, false)
			if err != nil {
				log.Errorf("ProcessImageLayers: %s", err)
				// return tempIOCsFound, err
				continue
			}
			for i := range iocs {
				res <- i
			}
		}
	}()

	return res, nil
}

// Save container image as tar file in specified directory
// @parameters
// imageScan - Structure with details of the container image to scan
// @returns
// Error - Errors if any. Otherwise, returns nil
func (imageScan *ImageScan) saveImageData() error {
	imageName := imageScan.imageName
	outputParam := path.Join(imageScan.tempDir, imageTarFileName)
	drun, err := vessel.NewRuntime()
	if err != nil {
		return err
	}
	_, err = drun.Save(imageName, outputParam)

	if err != nil {
		return err
	}
	log.Infof("Image %s saved in %s", imageName, imageScan.tempDir)
	return nil
}

// Extract the contents of container image and save it in specified dir
// @parameters
// imageName - Name of the container image to save
// imageTarPath - Complete path where tarball of the image is stored
// extractPath - Complete path of directory where contents of image are to be extracted
// @returns
// string - directory where contents of image are extracted
// Error - Errors, if any. Otherwise, returns nil
func extractTarFile(imageName, imageTarPath string, extractPath string) (string, error) {
	log.Debug("Started extracting tar file %s", imageTarPath)

	path := extractPath

	// Extract the contents of image from tar file
	if err := untar(imageTarPath, path); err != nil {
		return "", err
	}

	log.Debug("Finished extracting tar file %s", imageTarPath)
	return path, nil
}

// Extract all the details from image manifest
// @parameters
// path - Complete path where image contents are extracted
// @returns
// manifestItem - The manifestItem containing details about image layers
// Error - Errors, if any. Otherwise, returns nil
func untar(tarName string, xpath string) (err error) {
	tarFile, err := os.Open(tarName)
	if err != nil {
		return err
	}
	defer func() {
		err = tarFile.Close()
	}()

	absPath, err := filepath.Abs(xpath)
	if err != nil {
		return err
	}

	tr := tar.NewReader(tarFile)
	if strings.HasSuffix(tarName, ".gz") || strings.HasSuffix(tarName, ".gzip") {
		gz, err := gzip.NewReader(tarFile)
		if err != nil {
			return err
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	}

	// untar each segment
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// determine proper file path info
		finfo := hdr.FileInfo()
		fileName := hdr.Name
		if filepath.IsAbs(fileName) {
			fileName, err = filepath.Rel("/", fileName)
			if err != nil {
				return err
			}
		}

		absFileName := filepath.Join(absPath, fileName)
		if strings.Contains(fileName, "/") {
			relPath := strings.Split(fileName, "/")
			var absDirPath string
			if len(relPath) > 1 {
				dirs := relPath[0 : len(relPath)-1]
				absDirPath = filepath.Join(absPath, strings.Join(dirs, "/"))
			}
			if err := os.MkdirAll(absDirPath, 0755); err != nil {
				log.Warn(err.Error())
			}
		}

		if finfo.Mode().IsDir() {
			if err := os.MkdirAll(absFileName, 0755); err != nil {
				return err
			}
			continue
		}

		// create new file with original file mode
		file, err := os.OpenFile(absFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, finfo.Mode().Perm())
		if err != nil {
			return err
		}
		n, cpErr := io.Copy(file, tr)
		if closeErr := file.Close(); closeErr != nil { // close file immediately
			return err
		}
		if cpErr != nil {
			return cpErr
		}
		if n != finfo.Size() {
			return errors.New(fmt.Sprintf("unexpected bytes written: wrote %d, want %d", n, finfo.Size()))
		}
	}
	return nil
}

// Extract all the details from image manifest
// @parameters
// path - Complete path where image contents are extracted
// @returns
// manifestItem - The manifestItem containing details about image layers
// Error - Errors, if any. Otherwise, returns nil
func extractDetailsFromManifest(path string) (manifestItem, error) {
	mf, err := os.Open(path + "/manifest.json")
	if err != nil {
		return manifestItem{}, err
	}
	defer mf.Close()

	var manifest []manifestItem
	if err = json.NewDecoder(mf).Decode(&manifest); err != nil {
		return manifestItem{}, err
	} else if len(manifest) != 1 {
		return manifestItem{}, err
	}
	var layerIds []string
	for _, layer := range manifest[0].Layers {
		trimmedLayerId := strings.TrimSuffix(layer, "/layer.tar")
		// manifests saved by some versions of skopeo has .tar extentions
		trimmedLayerId = strings.TrimSuffix(trimmedLayerId, ".tar")
		layerIds = append(layerIds, trimmedLayerId)
	}
	manifest[0].LayerIds = layerIds
	// ImageScan.imageManifest = manifest[0]
	return manifest[0], nil
}

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
			log.Debug("Could not get exit code for failed program: %v, %v", name, args)
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
	ImageId string
}

func (s *Scanner) ExtractAndScanImage(image string) (*ImageExtractionResult, error) {
	tempDir, err := core.GetTmpDir(*s.ImageName, *s.TempDirectory)
	if err != nil {
		return nil, err
	}

	imageScan := ImageScan{imageName: image, imageId: "", tempDir: tempDir}
	err = imageScan.extractImage(true)
	if err != nil {
		return nil, err
	}

	IOCs, err := imageScan.scan(s)

	if err != nil {
		return nil, err
	}
	return &ImageExtractionResult{ImageId: imageScan.imageId, IOCs: IOCs}, nil
}

func (s *Scanner) ExtractAndScanImageStream(image string) (chan output.IOCFound, error) {
	tempDir, err := core.GetTmpDir(*s.ImageName, *s.TempDirectory)
	if err != nil {
		core.DeleteTmpDir(tempDir)
		return nil, err
	}

	imageScan := ImageScan{imageName: image, imageId: "", tempDir: tempDir}
	err = imageScan.extractImage(true)
	if err != nil {
		core.DeleteTmpDir(tempDir)
		return nil, err
	}

	IOCs, err := imageScan.scanStream(s)
	if err != nil {
		return nil, err
	}
	res := make(chan output.IOCFound, output_channel_size)
	go func() {
		defer core.DeleteTmpDir(tempDir)
		for i := range IOCs {
			res <- i
		}
		close(res)
	}()

	return res, nil

}

func (s *Scanner) ExtractAndScanFromTar(tarFolder string) (*ImageExtractionResult, error) {
	// defer core.DeleteTmpDir(tarFolder)
	imageScan := ImageScan{imageName: *s.ImageName, imageId: "", tempDir: tarFolder}
	err := imageScan.extractImage(false)
	if err != nil {
		return nil, err
	}
	IOCs, err := imageScan.scan(s)

	if err != nil {
		return nil, err
	}
	return &ImageExtractionResult{ImageId: imageScan.imageId, IOCs: IOCs}, nil
}
