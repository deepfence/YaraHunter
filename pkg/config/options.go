package config

import (
	"flag"
	"os"

	"github.com/deepfence/YaraHunter/utils"
)

var (
	product string = utils.GetEnvOrDefault("DEEPFENCE_PRODUCT", "ThreatMapper")
	license string = utils.GetEnvOrDefault("DEEPFENCE_LICENSE", "")
)

const (
	JSONOutput  = "json"
	TableOutput = "table"
)

type Options struct {
	Threads              *int
	DebugLevel           *string
	MaximumFileSize      *int64
	TempDirectory        *string
	Local                *string
	HostMountPath        *string
	ConfigPath           *string
	ImageName            *string
	MaxIOC               *uint
	ContainerID          *string
	ContainerNS          *string
	SocketPath           *string
	RulesPath            *string
	FailOnCompileWarning *bool
	WorkersPerScan       *int
	InactiveThreshold    *int
	OutFormat            *string
	ConsoleURL           *string
	ConsolePort          *int
	DeepfenceKey         *string
	FailOnCount          *int
	FailOnHighCount      *int
	FailOnMediumCount    *int
	FailOnLowCount       *int
	RulesListingURL      *string
	EnableUpdater        *bool
	Product              *string
	Version              *string
	License              *string
	LogLevel             *string
}

func ParseOptions() (*Options, error) {
	options := &Options{
		LogLevel:             flag.String("log-level", "info", "Log levels are one of error, warn, info, debug. Only levels higher than the log-level are displayed"),
		RulesPath:            flag.String("rules-path", "/home/deepfence/usr", "All .yar and .yara files in the given directory will be compiled"),
		FailOnCompileWarning: flag.Bool("fail-on-rule-compile-warn", false, "Fail if yara rule compilation has warnings"),
		Threads:              flag.Int("threads", 0, "Number of concurrent threads (default number of logical CPUs)"),
		DebugLevel:           flag.String("debug-level", "ERROR", "Debug levels are one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG. Only levels higher than the debug-level are displayed"),
		MaximumFileSize:      flag.Int64("maximum-file-size", 32*1024*1024, "Maximum file size to process in bytes"),
		TempDirectory:        flag.String("temp-directory", os.TempDir(), "Directory to process and store repositories/matches"),
		Local:                flag.String("local", "", "Specify local directory (absolute path) which to scan. Scans only given directory recursively."),
		HostMountPath:        flag.String("host-mount-path", "", "If scanning the host, specify the host mount path for path exclusions to work correctly."),
		ConfigPath:           flag.String("config-path", "", "Searches for config.yaml from given directory. If not set, tries to find it from YaraHunter binary's and current directory"),
		ImageName:            flag.String("image-name", "", "Name of the image along with tag to scan for IOC"),
		MaxIOC:               flag.Uint("max-ioc", 1000, "Maximum number of indicator of compromise to find in one container image or file system."),
		ContainerID:          flag.String("container-id", "", "Id of existing container ID"),
		ContainerNS:          flag.String("container-ns", "", "Namespace of existing container to scan, empty for docker runtime"),
		SocketPath:           flag.String("socket-path", "", "The gRPC server unix socket path"),
		WorkersPerScan:       flag.Int("workers-per-scan", 1, "Number of concurrent workers per scan"),
		InactiveThreshold:    flag.Int("inactive-threshold", 600, "Threshold for Inactive scan in seconds"),
		OutFormat:            flag.String("output", TableOutput, "Output format: json or table"),
		ConsoleURL:           flag.String("console-url", "", "Deepfence Management Console URL"),
		ConsolePort:          flag.Int("console-port", 443, "Deepfence Management Console Port"),
		DeepfenceKey:         flag.String("deepfence-key", "", "Deepfence key for auth"),
		FailOnCount:          flag.Int("fail-on-count", -1, "Exit with status 1 if number of malwares found is >= this value (Default: -1)"),
		FailOnHighCount:      flag.Int("fail-on-high-count", -1, "Exit with status 1 if number of high malwares found is >= this value (Default: -1)"),
		FailOnMediumCount:    flag.Int("fail-on-medium-count", -1, "Exit with status 1 if number of medium malwares found is >= this value (Default: -1)"),
		FailOnLowCount:       flag.Int("fail-on-low-count", -1, "Exit with status 1 if number of low malwares found is >= this value (Default: -1)"),
		RulesListingURL:      flag.String("rules-listing-url", "https://threat-intel.deepfence.io/yara-rules/listing.json", "Deepfence threat intel yara rules listing (Default: threat-intel.deepfence.io/yara-rules/listing.json)"),
		EnableUpdater:        flag.Bool("enable-updater", true, "Enable rules updater (Default: true)"),
		Product:              flag.String("product", product, "Deepfence Product type can be ThreatMapper or ThreatStryker, also supports env var DEEPFENCE_PRODUCT"),
		License:              flag.String("license", license, "TheratMapper or ThreatStryker license, also supports env var DEEPFENCE_LICENSE"),
	}
	flag.Parse()
	return options, nil
}

// NewDefaultOptions returns the default options for the YaraHunter without flag parsing
func NewDefaultOptions() *Options {
	var rulePath = "/home/deepfence/usr"
	var failOnCompileWarning = false
	var threads = 0
	var debugLevel = "ERROR"
	var maximumFileSize = int64(32 * 1024 * 1024)
	var tempDirectory = os.TempDir()
	var emptyValue = ""
	var maxIOC = uint(1000)
	var inactiveThreshold = 600
	return &Options{
		RulesPath:            &rulePath,
		FailOnCompileWarning: &failOnCompileWarning,
		Threads:              &threads,
		DebugLevel:           &debugLevel,
		MaximumFileSize:      &maximumFileSize,
		TempDirectory:        &tempDirectory,
		InactiveThreshold:    &inactiveThreshold,
		Local:                &emptyValue,
		HostMountPath:        &emptyValue,
		ConfigPath:           &emptyValue,
		ImageName:            &emptyValue,
		MaxIOC:               &maxIOC,
		ContainerID:          &emptyValue,
		ContainerNS:          &emptyValue,
		SocketPath:           &emptyValue,
		Product:              &product,
		License:              &license,
	}
}
