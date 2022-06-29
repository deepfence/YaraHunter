package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"fmt"

	"github.com/deepfence/IOCScanner/core"
	"github.com/deepfence/IOCScanner/output"
	"github.com/deepfence/vessel"
	yr "github.com/hillu/go-yara/v4"
)

// Data type to store details about the container image after parsing manifest
type manifestItem struct {
	Config   string
	RepoTags []string
	Layers   []string
	LayerIds []string `json:",omitempty"`
}

var (
	imageTarFileName = "save-output.tar"
	maxIOCsExceeded  = errors.New("number of IOCs exceeded max-ioc")
	fd               uintptr
	rules            *yr.Rules
	RuleFiles        []string
	iocFile          *os.File
)

type extvardefs map[string]interface{}

const filescan = 0
const procscan = 1

var extvars = map[int]extvardefs{
	filescan: {
		"filename":  "",
		"filepath":  "",
		"extension": "",
		"filetype":  "",
	},
	procscan: {
		"pid":        -1,
		"executable": "",
	},
}

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
			core.GetSession().Log.Error("scanImage: Could not save container image: %s. Check if the image name is correct.", err)
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
	tempDir := imageScan.tempDir
	defer core.DeleteTmpDir(tempDir)

	tempIOCsFound, err := imageScan.processImageLayers(tempDir)
	if err != nil {
		core.GetSession().Log.Error("scanImage: %s", err)
		return tempIOCsFound, err
	}

	return tempIOCsFound, nil
}

func compile(purpose int, inputfiles []string, failOnWarnings bool) (*yr.Rules, error) {
	var c *yr.Compiler
	session := core.GetSession()
	var err error
	var paths []string
	if c, err = yr.NewCompiler(); err != nil {
		return nil, err
	}

	for k, v := range extvars[purpose] {
		if err = c.DefineVariable(k, v); err != nil {
			return nil, err
		}
	}

	for _, path := range inputfiles {
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return nil, errors.New("No YARA rule files found")
	}
	for _, path := range paths {
		// We use the include callback function to actually read files
		// because yr_compiler_add_string() does not accept a file
		// name.
		fmt.Println("include", path)
		if err = c.AddString(fmt.Sprintf(`include "%s"`, path), ""); err != nil {
			return nil, err
		}
	}
	purposeStr := [...]string{"file", "process"}[purpose]
	rs, err := c.GetRules()
	if err != nil {
		for _, e := range c.Errors {
			session.Log.Error("YARA compiler error in %s ruleset: %s:%d %s",
				purposeStr, e.Filename, e.Line, e.Text)
		}
		return nil, fmt.Errorf("%d YARA compiler errors(s) found, rejecting %s ruleset",
			len(c.Errors), purposeStr)
	}
	if len(c.Warnings) > 0 {
		for _, w := range c.Warnings {
			session.Log.Info("YARA compiler warning in %s ruleset: %s:%d %s",
				purposeStr, w.Filename, w.Line, w.Text)
		}
		if failOnWarnings {
			return nil, fmt.Errorf("%d YARA compiler warning(s) found, rejecting %s ruleset",
				len(c.Warnings), purposeStr)
		}
	}
	if len(rs.GetRules()) == 0 {
		return nil, errors.New("No YARA rules defined")
	}
	return rs, nil
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
func ScanIOCInDir(layer string, baseDir string, fullDir string, isFirstIOC *bool,
	numIOCs *uint, matchedRuleSet map[uint]uint) ([]output.IOCFound, error) {
	var tempIOCsFound []output.IOCFound
	var err error
	var matches yr.MatchRules
	if matchedRuleSet == nil {
		matchedRuleSet = make(map[uint]uint)
	}

	if layer != "" {
		core.UpdateDirsPermissionsRW(fullDir)
	}
	session := core.GetSession()
	ruleFiles := []string{"filescan.yar"}
	rules, err = compile(filescan, ruleFiles, true)

	if err != nil {
		session.Log.Error("compiling rules issue: %s", err)
	}

	maxFileSize := *session.Options.MaximumFileSize * 1024
	var file core.MatchFile
	var relPath string

	walkErr := filepath.Walk(fullDir, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
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

		if f.IsDir() && (f.Name() == ".file" || f.Name() == ".vol" || f.Name() == "cpuid" ||
			f.Name() == "msr" || f.Name() == "cpuid" || f.Name() == "cpu_dma_latency" || f.Name() == "cuse") {
			return filepath.SkipDir
		}
		if f.IsDir() {
			if core.IsSkippableDir(scanDirPath, baseDir) {
				return filepath.SkipDir
			}
			return nil
		}

		if f.Name() == ".file" || f.Name() == ".vol" {
			return filepath.SkipDir
		}

		if uint(f.Size()) > maxFileSize || core.IsSkippableFileExtension(path) {
			return nil
		}

		if uint(f.Size()) > maxFileSize || core.IsSkippableFileExtension(path) {
			return nil
		}
		// No need to scan sym links. This avoids hangs when scanning stderr, stdour or special file descriptors
		// Also, the pointed files will anyway be scanned directly
		if core.IsSymLink(path) {
			return nil
		}

		file = core.NewMatchFile(path)

		relPath, err = filepath.Rel(filepath.Join(baseDir, layer), file.Path)
		if err != nil {
			session.Log.Warn("scanIOCsInDir: Couldn't remove prefix of path: %s %s %s",
				baseDir, layer, file.Path)
			relPath = file.Path
		}

		// Add RW permissions for reading and deleting contents of containers, not for regular file system
		if layer != "" {
			err = os.Chmod(file.Path, 0600)
			if err != nil {
				session.Log.Error("scanIOCsInDir changine file permission: %s", err)
			}
		}

		//fmt.Println("test step rules", rules)
		if len(file.Extension) > 0 {

		}
		iocFile, err := os.OpenFile(file.Path, os.O_RDWR|os.O_CREATE, 0777)
		if err != nil {
			session.Log.Error("scanIOCsInDir reading file: %s", err)
			// return tempIOCsFound, err
		} else {
			// fmt.Println(relPath, file.Filename, file.Extension, layer)
			fd := iocFile.Fd()

			err = rules.ScanFileDescriptor(fd, 0, 1*time.Minute, &matches)
			if err != nil {
				var buf []byte
				if buf, err = ioutil.ReadAll(iocFile); err != nil {
					session.Log.Info("relPath: %s, Filename: %s, Extension: %s, layer: %s",
						relPath, file.Filename, file.Extension, layer)
					session.Log.Error("scanIOCsInDir: %s", err)
					return err
				}
				err = rules.ScanMem(buf, 0, 1*time.Minute, &matches)
			}
			fmt.Println("=========================")
			fmt.Println(file.Path)
			for _, m := range matches {
				fmt.Printf("------------------------\n")
				fmt.Printf("%v \n", m.Rule)
				fmt.Printf("%v \n", m.Namespace)
				for _, str := range m.Strings {
					fmt.Println(str.Name)
					fmt.Println(string(str.Data))
				}
				fmt.Printf("%v \n", m.Metas)
				// TODO: change the fields in IOCFound struct to accept above fields
				//ioc := output.IOCFound{}
				//tempIOCsFound = append(tempIOCsFound, ioc)
			}
		}
		// Don't report IOCs if number of IOCs exceeds MAX value
		if *numIOCs >= *session.Options.MaxIOC {
			return maxIOCsExceeded
		}
		return nil
	})
	if walkErr != nil {
		if walkErr == maxIOCsExceeded {
			session.Log.Warn("filepath.Walk: %s", walkErr)
			fmt.Printf("filepath.Walk: %s\n", walkErr)
		} else {
			session.Log.Error("Error in filepath.Walk: %s", walkErr)
			fmt.Printf("Error in filepath.Walk: %s\n", walkErr)
		}
	}
	if *session.Options.Quiet {
		output.PrintColoredIOC(tempIOCsFound, isFirstIOC)
	}
	return tempIOCsFound, nil
}

// Extract all the layers of the container image and then find IOCs in each layer one by one
// @parameters
// imageScan - Structure with details of the container image to scan
// imageManifestPath - Complete path of directory where manifest of image has been extracted
// @returns
// []output.IOCFound - List of all IOCs found
// Error - Errors if any. Otherwise, returns nil
func (imageScan *ImageScan) processImageLayers(imageManifestPath string) ([]output.IOCFound, error) {
	var tempIOCsFound []output.IOCFound
	var err error
	var isFirstIOC bool = true

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
			// Don't stop. Print error and continue with remaning extracted files and other layers
			// return tempIOCsFound, error
		}
		core.GetSession().Log.Debug("Analyzing dir: %s", targetDir)
		IOCs, err = ScanIOCInDir(layerIDs[i], extractPath, targetDir, &isFirstIOC, &imageScan.numIOCs, matchedRuleSet)
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
	fmt.Printf("Scanning image %s for IOCs...\n", outputParam)
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
		fmt.Println(err)
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
				fmt.Println(err.Error())
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
			fmt.Println(err.Error())
			return err
		}
		// fmt.Printf("x %s\n", absFileName)
		n, cpErr := io.Copy(file, tr)
		if closeErr := file.Close(); closeErr != nil { // close file immediately
			fmt.Println("clserr:" + closeErr.Error())
			return err
		}
		if cpErr != nil {
			fmt.Println("copyErr:" + cpErr.Error())
			return cpErr
		}
		if n != finfo.Size() {
			return fmt.Errorf("unexpected bytes written: wrote %d, want %d", n, finfo.Size())
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
			log.Printf("Could not get exit code for failed program: %v, %v", name, args)
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

	imageScan := ImageScan{imageName: imageName, imageId: "", tempDir: tarFolder}
	err := imageScan.extractImage(false)

	if err != nil {
		return nil, err
	}

	IOCs, err := imageScan.scan()

	if err != nil {
		return nil, err
	}
	return &ImageExtractionResult{ImageId: imageScan.imageId, IOCs: IOCs}, nil
}
