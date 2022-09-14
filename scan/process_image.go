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
	"time"

	"fmt"

	"github.com/deepfence/YaRadare/core"
	"github.com/deepfence/YaRadare/output"
	"github.com/deepfence/vessel"
	yr "github.com/hillu/go-yara/v4"
	"github.com/spf13/afero"
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
	session          = *core.GetSession()
	maxFileSize      = *session.Options.MaximumFileSize
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
	imageName := imageScan.imageName
	tempDir := imageScan.tempDir
	imageScan.numIOCs = 0

	if saveImage {
		err := imageScan.saveImageData()
		if err != nil {
			core.GetSession().Log.Error("image does not exist: %s", err)
			return err
		}
	}

	_, err := extractTarFile(imageName, path.Join(tempDir, imageTarFileName), tempDir)
	if err != nil {
		core.GetSession().Log.Error("scanImage: Could not extract image tar file: %s", err)
		return err
	}

	imageManifest, err := extractDetailsFromManifest(tempDir)
	if err != nil {
		core.GetSession().Log.Error("ProcessImageLayers: Could not get image's history: %s,"+
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
func (imageScan *ImageScan) scan() ([]output.IOCFound, error) {
	fmt.Println("reached scan function")
	tempDir := imageScan.tempDir
	defer core.DeleteTmpDir(tempDir)

	tempIOCsFound, err := imageScan.processImageLayers(tempDir)
	if err != nil {
		core.GetSession().Log.Error("scanImage: %s", err)
		return tempIOCsFound, err
	}

	return tempIOCsFound, nil
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

func ScanFilePath(fs afero.Fs, path string, iocs **[]output.IOCFound, layer string) (err error) {
	f, err := fs.Open(path)
	if err != nil {
		fmt.Println("Error opening file ", path, err)
		session.Log.Error("Error: %v", err)
		return err
	}
	defer f.Close()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		fmt.Println("Could not seek to start of file ", path, err)
		session.Log.Error("Could not seek to start of file %s: %v", path, err)
		return err
	}
	if e := ScanFile(f, &iocs, layer); err == nil && e != nil {
		fmt.Println("the file error is", e)
		err = e
	}
	return
}

func ScanFile(f afero.File, iocs ***[]output.IOCFound, layer string) error {
	var (
		matches yr.MatchRules
		err     error
	)
	if err != nil {
		return err
	}

	type ruleVariable struct {
		name  string
		value interface{}
	}

	if  filepath.Ext(f.Name()) != ""  {

		variables := []ruleVariable{
			{"filename", filepath.ToSlash(filepath.Base(f.Name()))},
			{"filepath", filepath.ToSlash(f.Name())},
			{"extension", filepath.Ext(f.Name())},
		}
		fmt.Println("the variable values here are",variables)
		for _, v := range variables {
			fmt.Printf("%v\n",v)
			if v.value != nil  {
				if err = session.YaraRules.DefineVariable(v.name, v.value); err != nil {
					fmt.Println("the error is", err)
					return err
				}
			} 
		}

		fmt.Println("reached next line")

		fi, err := f.Stat()
		if err != nil {
			// report.AddStringf("yara: %s: Error accessing file information, error=%s",
			// 	f.Name(), err.Error())
			return err
		}
		fileName := f.Name()
		fmt.Println("reached next filename", fileName)
		hostMountPath := *session.Options.HostMountPath
		if hostMountPath != "" {
			fileName = strings.TrimPrefix(fileName, hostMountPath)
		}
		if maxFileSize > 0 && fi.Size() > maxFileSize {
			session.Log.Debug("\nyara: %v: Skipping large file, size=%v, max_size=%v", fileName, fi.Size(), maxFileSize)
			return nil
		}
		if f, ok := f.(*os.File); ok {
			fd := f.Fd()
			fmt.Println("reached inside File Descriptor", fd)
			err = session.YaraRules.ScanFileDescriptor(fd, 0, 1*time.Minute, &matches)
			if err != nil {
				fmt.Println("Scan File Descriptor error", err)
			}
		} else {
			var buf []byte
			if buf, err = ioutil.ReadAll(f); err != nil {
				session.Log.Error("yara: %s: Error reading file, error=%s",
					fileName, err.Error())
				fmt.Println("Error reading file, error", fileName, err.Error())
				return err
			}
			err = session.YaraRules.ScanMem(buf, 0, 1*time.Minute, &matches)
			if err != nil {
				fmt.Println("Scan File Mmory Error", err)
			}

		}
		var iocsFound []output.IOCFound
		totalMatchesStringData := make([]string, 0)
		for _, m := range matches {
			fmt.Println("test rule", m.Rule)
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
			fmt.Println(m.Rule, fileName)

			iocsFound = append(iocsFound, output.IOCFound{
				RuleName:         m.Rule,
				CategoryName:     m.Tags,
				StringsToMatch:   matchesStringData,
				Meta:             matchesMetaData,
				CompleteFilename: fileName,
			})
			fmt.Println(m.Rule, iocsFound)
		}
		var fileMat fileMatches
		fileMat.fileName = fileName
		fileMat.iocs = iocsFound
		updatedSeverity, updatedScore := calculateSeverity(totalMatchesStringData, "low", 0)
		fileMat.updatedSeverity = updatedSeverity
		fileMat.updatedScore = updatedScore
		fmt.Println("file matches",fileMat)
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
							if len(metaSplit[0]) > 0 {
								str := []string{"The matched rule file's ", metaSplit[0], " is", strings.Replace(metaSplit[1], "\n", "", -1) + "."}
								summary = summary + strings.Join(str, " ")
							}
						}
					}
				}
				m.Summary = summary
				*(*(*iocs)) = append(*(*(*iocs)), m)
			}
		}
		fmt.Println("file match iocs",iocs)
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
func ScanIOCInDir(layer string, baseDir string, fullDir string, matchedRuleSet map[uint]uint, iocs *[]output.IOCFound) error {
	var fs afero.Fs
	if layer != "" {
		session.Log.Info("Scan results in selected image with layer ", layer)
	}
	if matchedRuleSet == nil {
		matchedRuleSet = make(map[uint]uint)
	}

	if layer != "" {
		core.UpdateDirsPermissionsRW(fullDir)
	}

	// maxFileSize := *session.Options.MaximumFileSize * 1024
	// var file core.MatchFile
	// var relPath string
	fs = afero.NewOsFs()
	afero.Walk(fs, fullDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("error", err)
			return nil
		}

		var scanDirPath string
		if layer != "" {
			scanDirPath = strings.TrimPrefix(path, baseDir+"/"+layer)
			if scanDirPath == "" {
				scanDirPath = "/"
			}
		} else {
			scanDirPath = path
		}

		if info.IsDir() {
			if core.IsSkippableDir(fs, path, baseDir) {
				return filepath.SkipDir
			}
			return nil
		}
		const specialMode = os.ModeSymlink | os.ModeDevice | os.ModeNamedPipe | os.ModeSocket | os.ModeCharDevice
		if info.Mode()&specialMode != 0 {
			return nil
		}
		if core.IsSkippableFileExtension(path) {
			return nil
		}
		if err = ScanFilePath(fs, path, &iocs, layer); err != nil {

			fmt.Println("Scan Directory Path iocs", err)
		}
		return nil
	})

	return nil
}

// Extract all the layers of the container image and then find IOCs in each layer one by one
// @parameters
// imageScan - Structure with details of the container image to scan
// imageManifestPath - Complete path of directory where manifest of image has been extracted
// @returns
// []output.IOCFound - List of all IOCs found
// Error - Errors if any. Otherwise, returns nil
func (imageScan *ImageScan) processImageLayers(imageManifestPath string) ([]output.IOCFound, error) {
	fmt.Println("reached process image layers")
	var tempIOCsFound []output.IOCFound
	var err error

	// extractPath - Base directory where all the layers should be extracted to
	extractPath := path.Join(imageManifestPath, core.ExtractedImageFilesDir)
	layerIDs := imageScan.imageManifest.LayerIds
	layerPaths := imageScan.imageManifest.Layers
	matchedRuleSet := make(map[uint]uint)

	loopCntr := len(layerPaths)
	var IOCs []output.IOCFound
	for i := 0; i < loopCntr; i++ {
		core.GetSession().Log.Debug("Analyzing layer path: %s", layerPaths[i])
		core.GetSession().Log.Debug("Analyzing layer: %s", layerIDs[i])
		// savelayerID = layerIDs[i]
		completeLayerPath := path.Join(imageManifestPath, layerPaths[i])
		targetDir := path.Join(extractPath, layerIDs[i])
		core.GetSession().Log.Info("Complete layer path: %s", completeLayerPath)
		core.GetSession().Log.Info("Extracted to directory: %s", targetDir)
		err = core.CreateRecursiveDir(targetDir)
		if err != nil {
			core.GetSession().Log.Error("ProcessImageLayers: Unable to create target directory"+
				" to extract image layers... %s", err)
			return tempIOCsFound, err
		}

		_, error := extractTarFile("", completeLayerPath, targetDir)
		if error != nil {
			core.GetSession().Log.Error("ProcessImageLayers: Unable to extract image layer. Reason = %s", error.Error())
			// Don't stop. Print error and continue with remaining extracted files and other layers
			// return tempIOCsFound, error
		}
		core.GetSession().Log.Debug("Analyzing dir: %s", targetDir)
		err = ScanIOCInDir(layerIDs[i], extractPath, targetDir, matchedRuleSet, &IOCs)
		tempIOCsFound = append(tempIOCsFound, IOCs...)
		if err != nil {
			core.GetSession().Log.Error("ProcessImageLayers: %s", err)
			// return tempIOCsFound, err
		}

		// Don't report IOCs if number of IOCs exceeds MAX value
		if imageScan.numIOCs >= *core.GetSession().Options.MaxIOC {
			return tempIOCsFound, nil
		}
	}

	return tempIOCsFound, nil
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
	core.GetSession().Log.Info("Image %s saved in %s", imageName, imageScan.tempDir)
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
	core.GetSession().Log.Debug("Started extracting tar file %s", imageTarPath)

	path := extractPath

	// Extract the contents of image from tar file
	if err := untar(imageTarPath, path); err != nil {
		return "", err
	}

	core.GetSession().Log.Debug("Finished extracting tar file %s", imageTarPath)
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
				session.Log.Warn(err.Error())
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
			core.GetSession().Log.Debug("Could not get exit code for failed program: %v, %v", name, args)
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

func ExtractAndScanImage(image string) (*ImageExtractionResult, error) {
	tempDir, err := core.GetTmpDir(image)
	if err != nil {
		return nil, err
	}
	// defer core.DeleteTmpDir(tempDir)

	imageScan := ImageScan{imageName: image, imageId: "", tempDir: tempDir}
	err = imageScan.extractImage(true)

	if err != nil {
		return nil, err
	}

	IOCs, err := imageScan.scan()

	if err != nil {
		return nil, err
	}
	return &ImageExtractionResult{ImageId: imageScan.imageId, IOCs: IOCs}, nil
}

func ExtractAndScanFromTar(tarFolder string, imageName string) (*ImageExtractionResult, error) {
	// defer core.DeleteTmpDir(tarFolder)
	fmt.Println("image scan")
	imageScan := ImageScan{imageName: imageName, imageId: "", tempDir: tarFolder}
	err := imageScan.extractImage(false)

	if err != nil {
		return nil, err
	}
	fmt.Println("image scan before iocs")
	IOCs, err := imageScan.scan()

	if err != nil {
		return nil, err
	}
	return &ImageExtractionResult{ImageId: imageScan.imageId, IOCs: IOCs}, nil
}
