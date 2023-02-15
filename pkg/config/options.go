package config

import (
	"flag"
	"os"
)

const (
	TempDirSuffix          = "YaRadare"
	ExtractedImageFilesDir = "ExtractedFiles"
)

type Options struct {
	Threads              *int
	DebugLevel           *string
	MaximumFileSize      *int64
	TempDirectory        *string
	Local                *string
	HostMountPath        *string
	ConfigPath           *string
	OutputPath           *string
	JsonFilename         *string
	ImageName            *string
	MaxIOC               *uint
	ContainerId          *string
	ContainerNS          *string
	SocketPath           *string
	HttpPort             *string
	StandAloneHttpPort   *string
	RulesPath            *string
	FailOnCompileWarning *bool
}

func ParseOptions() (*Options, error) {
	options := &Options{
		RulesPath:            flag.String("rules-path", "/home/deepfence/usr", "All .yar and .yara files in the given directory will be compiled"),
		FailOnCompileWarning: flag.Bool("fail-on-rule-compile-warn", false, "Fail if yara rule compilation has warnings"),
		Threads:              flag.Int("threads", 0, "Number of concurrent threads (default number of logical CPUs)"),
		DebugLevel:           flag.String("debug-level", "ERROR", "Debug levels are one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG. Only levels higher than the debug-level are displayed"),
		MaximumFileSize:      flag.Int64("maximum-file-size", 32*1024*1024, "Maximum file size to process in bytes"),
		TempDirectory:        flag.String("temp-directory", os.TempDir(), "Directory to process and store repositories/matches"),
		Local:                flag.String("local", "", "Specify local directory (absolute path) which to scan. Scans only given directory recursively."),
		HostMountPath:        flag.String("host-mount-path", "", "If scanning the host, specify the host mount path for path exclusions to work correctly."),
		ConfigPath:           flag.String("config-path", "", "Searches for config.yaml from given directory. If not set, tries to find it from YaRadare binary's and current directory"),
		OutputPath:           flag.String("output-path", "", "Output directory where json file will be stored. If not set, it will output to current directory"),
		JsonFilename:         flag.String("json-filename", "", "Output json file name. If not set, it will automatically create a filename based on image or dir name"),
		ImageName:            flag.String("image-name", "", "Name of the image along with tag to scan for IOC"),
		MaxIOC:               flag.Uint("max-ioc", 1000, "Maximum number of indicator of compromise to find in one container image or file system."),
		ContainerId:          flag.String("container-id", "", "Id of existing container ID"),
		ContainerNS:          flag.String("container-ns", "", "Namespace of existing container to scan, empty for docker runtime"),
		SocketPath:           flag.String("socket-path", "", "The gRPC server unix socket path"),
		HttpPort:             flag.String("http-port", "", "When set the http server will come up at port with df es as output"),
		StandAloneHttpPort:   flag.String("standalone-http-port", "", "use to run malware scanner as a standalone service"),
	}
	flag.Parse()
	return options, nil
}
