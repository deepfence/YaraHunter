package core

import (
	"flag"
	"os"
)

const (
	TempDirSuffix          = "IOCScanning"
	ExtractedImageFilesDir = "ExtractedFiles"
)

type Options struct {
	Threads         *int
	LogLevel        *string
	MaximumFileSize *int64
	TempDirectory   *string
	Local           *string
	HostMountPath   *string
	ConfigPath      *string
	OutputPath      *string
	JsonFilename    *string
	ImageName       *string
	MaxIOC          *uint
	ContainerId     *string
	ContainerNS     *string
	RulesPath       *string
}

func ParseOptions() (*Options, error) {
	options := &Options{
		RulesPath:       flag.String("rules-path", "/home/deepfence/rules", "All .yar and .yara files in the given directory will be compiled"),
		Threads:         flag.Int("threads", 0, "Number of concurrent threads (default number of logical CPUs)"),
		LogLevel:        flag.String("log-level", "ERROR", "Log levels are one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG. Only levels higher than the log-level are displayed"),
		MaximumFileSize: flag.Int64("maximum-file-size", 32*1024*1024, "Maximum file size to process in bytes"),
		TempDirectory:   flag.String("temp-directory", os.TempDir(), "Directory to process and store repositories/matches"),
		Local:           flag.String("local", "", "Specify local directory (absolute path) which to scan. Scans only given directory recursively."),
		HostMountPath:   flag.String("host-mount-path", "", "If scanning the host, specify the host mount path for path exclusions to work correctly."),
		ConfigPath:      flag.String("config-path", "", "Searches for config.yaml from given directory. If not set, tries to find it from IOCScanner binary's and current directory"),
		OutputPath:      flag.String("output-path", ".", "Output directory where json file will be stored. If not set, it will output to current directory"),
		JsonFilename:    flag.String("json-filename", "", "Output json file name. If not set, it will automatically create a filename based on image or dir name"),
		ImageName:       flag.String("image-name", "", "Name of the image along with tag to scan for IOC"),
		MaxIOC:          flag.Uint("max-ioc", 1000, "Maximum number of IOC to find in one container image or file system."),
		ContainerId:     flag.String("container-id", "", "Id of existing container ID"),
		ContainerNS:     flag.String("container-ns", "", "Namespace of existing container to scan, empty for docker runtime"),
	}
	flag.Parse()
	return options, nil
}
