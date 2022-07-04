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

	"github.com/sirupsen/logrus"

	"fmt"

	"github.com/deepfence/IOCScanner/core"
	"github.com/deepfence/IOCScanner/core/sys"
	"github.com/deepfence/IOCScanner/output"
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
	rules            *yr.Rules
	maxFileSize      = *core.GetSession().Options.MaximumFileSize
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
		//fmt.Println("include", path)
		if err = c.AddString(fmt.Sprintf(`include "%s"`, path), ""); err != nil {
			return nil, err
		}
	}
	purposeStr := [...]string{"file", "process"}[purpose]
	rs, err := c.GetRules()
	fmt.Println("test warnings",c.Warnings)
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

func ScanFilePath(fs afero.Fs, path string) (err error) {
	f, err := fs.Open(path)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return err
	}
	defer f.Close()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		fmt.Printf("Could not seek to start of file %s: %v", path, err)
		return err
	}
	if e := ScanFile(f); err == nil && e != nil {
		err = e
	}

	return
}

func ScanFile(f afero.File) error {
	var (
		matches yr.MatchRules
		err     error
	)
	ruleFiles := []string{"malware.yar"}
	rules, err = compile(filescan, ruleFiles, true)
	if err != nil {
		return err
	}

	for _, v := range []struct {
		name  string
		value interface{}
	}{
		{"filename", filepath.ToSlash(filepath.Base(f.Name()))},
		{"filepath", filepath.ToSlash(f.Name())},
		{"extension", filepath.Ext(f.Name())},
	} {
		if err = rules.DefineVariable(v.name, v.value); err != nil {
			return err
		}
	}

	fi, err := f.Stat()
	if err != nil {
		// report.AddStringf("yara: %s: Error accessing file information, error=%s",
		// 	f.Name(), err.Error())
		return err
	}
	if maxFileSize > 0 && fi.Size() > maxFileSize {
		logrus.Debugf("\nyara: %v: Skipping large file, size=%v, max_size=%v", f.Name(), fi.Size(), maxFileSize)
		return nil
	}
	if f, ok := f.(*os.File); ok {
		fd := f.Fd()
		err = rules.ScanFileDescriptor(fd, 0, 1*time.Minute, &matches)
	} else {
		var buf []byte
		if buf, err = ioutil.ReadAll(f); err != nil {
			fmt.Printf("yara: %s: Error reading file, error=%s",
				f.Name(), err.Error())
			return err
		}
		err = rules.ScanMem(buf, 0, 1*time.Minute, &matches)
	}
	var tempIOCsFound []output.IOCFound
	totalmatchesStringData := make([]string, 0)
	for _, m := range matches {
		matchesStringData := make([]string, len(m.Strings))
		for _, str := range m.Strings {
			matchesStringData = append(matchesStringData, string(str.Data))
			totalmatchesStringData = append(totalmatchesStringData, string(str.Data))
		}
		matchesMeta := make([]string, len(m.Metas))
		matchesMetaData := make([]string, len(m.Strings))
		for _, strMeta := range m.Metas {
			matchesMeta = append(matchesMeta, strMeta.Identifier)
			matchesMetaData = append(matchesMetaData, fmt.Sprintf("value: %v", strMeta.Value))
		}

		tempIOCsFound = append(tempIOCsFound, output.IOCFound{
			RuleName:         m.Rule,
			StringsToMatch:   matchesStringData,
			Meta:             matchesMetaData,
			CompleteFilename: f.Name(),
		})
	}
	var fileMat fileMatches
	fileMat.fileName = f.Name()
	fileMat.iocs = tempIOCsFound

	updatedSeverity, updatedScore := calculateSeverity(totalmatchesStringData, "low", 0)
	fileMat.updatedSeverity = updatedSeverity
	fileMat.updatedScore = updatedScore
	var isFirstIOC bool = true
	if len(matches) > 0 {
		output.PrintColoredIOC(tempIOCsFound, &isFirstIOC)
	}

	return err
}
func typeToString(name [16]int8) string {
	var b []byte
	for _, c := range name {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func SkipDir(fs afero.Fs, path string) bool {
	file, err := fs.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	f, ok := file.(*os.File)
	if !ok {
		return false
	}
	var buf syscall.Statfs_t
	if err := syscall.Fstatfs(int(f.Fd()), &buf); err != nil {
		return false
	}
	switch uint32(buf.Type) {
	case
		// pseudo filesystems
		sys.BDEVFS_MAGIC,
		sys.BINFMTFS_MAGIC,
		sys.CGROUP_SUPER_MAGIC,
		sys.DEBUGFS_MAGIC,
		sys.EFIVARFS_MAGIC,
		sys.FUTEXFS_SUPER_MAGIC,
		sys.HUGETLBFS_MAGIC,
		sys.PIPEFS_MAGIC,
		sys.PROC_SUPER_MAGIC,
		sys.SELINUX_MAGIC,
		sys.SMACK_MAGIC,
		sys.SYSFS_MAGIC,
		// network filesystems
		sys.AFS_FS_MAGIC,
		sys.OPENAFS_FS_MAGIC,
		sys.CEPH_SUPER_MAGIC,
		sys.CIFS_MAGIC_NUMBER,
		sys.CODA_SUPER_MAGIC,
		sys.NCP_SUPER_MAGIC,
		sys.NFS_SUPER_MAGIC,
		sys.OCFS2_SUPER_MAGIC,
		sys.SMB_SUPER_MAGIC,
		sys.V9FS_MAGIC,
		sys.VMBLOCK_SUPER_MAGIC,
		sys.XENFS_SUPER_MAGIC:
		return true
	}
	return false
}

func GetPaths(path string) (paths []string) { return []string{path} }

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
	var fs afero.Fs
	if layer != "" {
		fmt.Println("Scan Results in selected image with layer-----", layer)
	}
	if matchedRuleSet == nil {
		matchedRuleSet = make(map[uint]uint)
	}

	if layer != "" {
		core.UpdateDirsPermissionsRW(fullDir)
	}
	session := core.GetSession()
	ruleFiles := []string{"malware.yar"}
	rules, err = compile(filescan, ruleFiles, true)
	if err != nil {
		session.Log.Error("compiling rules issue: %s", err)
	}

	// maxFileSize := *session.Options.MaximumFileSize * 1024
	// var file core.MatchFile
	// var relPath string

	fs = afero.NewOsFs()
	afero.Walk(fs, fullDir, func(path string, info os.FileInfo, err error) error {
		//printStats()
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if SkipDir(fs, path) {
				return filepath.SkipDir
			}
			return nil
		}
		const specialMode = os.ModeSymlink | os.ModeDevice | os.ModeNamedPipe | os.ModeSocket | os.ModeCharDevice
		if info.Mode()&specialMode != 0 {
			return nil
		}

		for _, path := range GetPaths(path) {
			//log.Debugf("Scanning %s...", path)
			if err = ScanFilePath(fs, path); err != nil {
				//log.Errorf("Error scanning file: %s: %v", path, err)
			}
		}
		return nil
	})

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
