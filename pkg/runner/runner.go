package runner

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
	"github.com/deepfence/YaraHunter/pkg/server"
	"github.com/deepfence/YaraHunter/pkg/yararules"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	log "github.com/sirupsen/logrus"
)

func StartYaraHunter(ctx context.Context, opts *config.Options, config *config.Config, extractorConfig cfg.Config) {

	if *opts.SocketPath == "" {
		runOnce(opts, config, extractorConfig)
		return
	}

	if err := server.RunGrpcServer(ctx, opts, config, constants.PluginName); err != nil {
		log.Panicf("main: failed to serve: %v", err)
	}
}

func runOnce(opts *config.Options, config *config.Config, extractorConfig cfg.Config) {
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

	scanner := scan.New(opts, config, extractorConfig, yaraScanner, "")
	//var ctx *tasks.ScanContext

	outputs := []output.IOCFound{}
	writeToArray := func(res output.IOCFound, scanID string) {
		outputs = append(outputs, res)
	}

	var st scan.ScanType
	nodeID := ""
	switch {
	case len(*opts.Local) > 0:
		st = scan.DIR_SCAN
		nodeID = *opts.Local
		log.Infof("scan for malwares in path %s", nodeID)
		err = scanner.Scan(st, "", *opts.Local, "", writeToArray)
		results = &output.JSONDirIOCOutput{DirName: nodeID, IOC: removeDuplicateIOCs(outputs)}
	case len(*opts.ImageName) > 0:
		st = scan.IMAGE_SCAN
		nodeID = *opts.ImageName
		log.Infof("Scanning image %s for IOC...", nodeID)
		//TODO ID
		err = scanner.Scan(st, "", *opts.ImageName, "", writeToArray)
		results = &output.JSONImageIOCOutput{ImageID: nodeID, IOC: removeDuplicateIOCs(outputs)}
	case len(*opts.ContainerID) > 0:
		st = scan.CONTAINER_SCAN
		nodeID = *opts.ContainerID
		log.Infof("scan for malwares in container %s", nodeID)
		err = scanner.Scan(st, "", nodeID, "", writeToArray)
		results = &output.JSONImageIOCOutput{ContainerID: nodeID, IOC: removeDuplicateIOCs(outputs)}
	default:
		err = fmt.Errorf("invalid request")
	}

	results.SetTime()

	if err != nil {
		println(err.Error())
		return
	}

	if len(*opts.ConsoleURL) != 0 && len(*opts.DeepfenceKey) != 0 {
		pub, err := output.NewPublisher(*opts.ConsoleURL, strconv.Itoa(*opts.ConsolePort), *opts.DeepfenceKey)
		if err != nil {
			log.Error(err.Error())
		}

		pub.SendReport(output.GetHostname(), *opts.ImageName, *opts.ContainerID, scan.ScanTypeString(st))
		scanID := pub.StartScan(nodeID, scan.ScanTypeString(st))
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

	if results == nil {
		log.Error("set either -local or -image-name flag")
		return
	}

	output.FailOn(counts,
		*opts.FailOnHighCount, *opts.FailOnMediumCount, *opts.FailOnLowCount, *opts.FailOnCount)
}
