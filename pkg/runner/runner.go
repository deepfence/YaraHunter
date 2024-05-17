package runner

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
	"github.com/deepfence/YaraHunter/pkg/server"
	"github.com/deepfence/YaraHunter/pkg/yararules"
	"github.com/khulnasoft-lab/golang_sdk/utils/tasks"
	log "github.com/sirupsen/logrus"
)

func StartYaraHunter(opts *config.Options, config *config.Config, newwg *sync.WaitGroup) {
	defer newwg.Done()

	if *opts.SocketPath == "" {
		runOnce(opts, config)
		return
	}

	if err := server.RunGrpcServer(opts, config, constants.PluginName); err != nil {
		log.Panicf("main: failed to serve: %v", err)
	}
}

func runOnce(opts *config.Options, config *config.Config) {
	var results IOCWriter

	yaraRules := yararules.New(*opts.RulesPath)
	err := yaraRules.Compile(constants.Filescan, *opts.FailOnCompileWarning)
	if err != nil {
		log.Errorf("error in runOnce compiling yara rules: %s", err)
		return
	}

	yaraScanner, err := yaraRules.NewScanner()
	if err != nil {
		log.Error("error in runOnce creating yara scanner:", err)
		return
	}

	scanner := scan.New(opts, config, yaraScanner, "")
	var ctx *tasks.ScanContext

	nodeType := ""
	nodeID := ""

	// Scan container image for IOC
	if len(*opts.ImageName) > 0 {
		nodeType = "image"
		nodeID = *opts.ImageName
		log.Infof("Scanning image %s for IOC...", *opts.ImageName)
		results, err = FindIOCInImage(ctx, scanner)
		if err != nil {
			log.Errorf("error scanning the image: %s", err)
			return
		}
	}

	// Scan local directory for IOC
	if len(*opts.Local) > 0 {
		nodeID = output.GetHostname()
		log.Infof("Scanning local directory: %s", *opts.Local)
		results, err = FindIOCInDir(ctx, scanner)
		if err != nil {
			log.Errorf("error scanning the dir: %s", err)
			return
		}
	}

	// Scan existing container for IOC
	if len(*opts.ContainerID) > 0 {
		nodeType = "container_image"
		nodeID = *opts.ContainerID
		log.Infof("Scanning container %s for IOC...", *opts.ContainerID)
		results, err = FindIOCInContainer(ctx, scanner)
		if err != nil {
			log.Errorf("error scanning the container: %s", err)
			return
		}
	}

	if results == nil {
		log.Error("set either -local or -image-name flag")
		return
	}

	if len(*opts.ConsoleURL) != 0 && len(*opts.DeepfenceKey) != 0 {
		pub, err := output.NewPublisher(*opts.ConsoleURL, strconv.Itoa(*opts.ConsolePort), *opts.DeepfenceKey)
		if err != nil {
			log.Error(err.Error())
		}

		pub.SendReport(output.GetHostname(), *opts.ImageName, *opts.ContainerID, nodeType)
		scanID := pub.StartScan(nodeID, nodeType)
		if len(scanID) == 0 {
			scanID = fmt.Sprintf("%s-%d", nodeID, time.Now().UnixMilli())
		}
		if err := pub.IngestSecretScanResults(scanID, results.GetIOC()); err != nil {
			log.Errorf("IngestSecretScanResults: %v", err)
		}
		log.Infof("scan id %s", scanID)
	}

	counts := output.CountBySeverity(results.GetIOC())

	if *opts.OutFormat == "json" {
		log.Infof("result severity counts: %+v", counts)
		err = results.WriteJSON()
		if err != nil {
			log.Errorf("error while writing IOC: %s", err)
			return
		}
	} else {
		fmt.Println("summary:")
		fmt.Printf("  total=%d high=%d medium=%d low=%d\n",
			counts.Total, counts.High, counts.Medium, counts.Low)
		err = results.WriteTable()
		if err != nil {
			log.Errorf("error while writing IOC: %s", err)
			return
		}
	}

	output.FailOn(counts,
		*opts.FailOnHighCount, *opts.FailOnMediumCount, *opts.FailOnLowCount, *opts.FailOnCount)
}
