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
	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
)

func StartYaraHunter(opts *config.Options, config *config.Config, newwg *sync.WaitGroup) {
	defer newwg.Done()

	if *opts.SocketPath != "" {
		err := server.RunGrpcServer(opts, config, constants.PLUGIN_NAME)
		if err != nil {
			log.Fatal("main: failed to serve: %v", err)
		}
	} else if *opts.HttpPort != "" {
		err := server.RunHttpServer(*opts.HttpPort)
		if err != nil {
			log.Fatal("main: failed to serve through http: %v", err)
		}
	} else if *opts.StandAloneHttpPort != "" {
		err := server.RunStandaloneHttpServer(*opts.StandAloneHttpPort)
		if err != nil {
			log.Fatal("main: failed to serve through http: %v", err)
		}
	} else {
		runOnce(opts, config)
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
	scanner.ReportStatus.Store(false)

	node_type := ""
	node_id := ""

	// Scan container image for IOC
	if len(*opts.ImageName) > 0 {
		node_type = "image"
		node_id = *opts.ImageName
		log.Info("Scanning image %s for IOC...\n", *opts.ImageName)
		results, err = FindIOCInImage(scanner)
		if err != nil {
			log.Errorf("error scanning the image: %s", err)
			return
		}
	}

	// Scan local directory for IOC
	if len(*opts.Local) > 0 {
		node_id = output.GetHostname()
		log.Info("[*] Scanning local directory: %s\n", color.BlueString(*opts.Local))
		results, err = FindIOCInDir(scanner)
		if err != nil {
			log.Errorf("error scanning the dir: %s", err)
			return
		}
	}

	// Scan existing container for IOC
	if len(*opts.ContainerId) > 0 {
		node_type = "container_image"
		node_id = *opts.ContainerId
		log.Info("Scanning container %s for IOC...\n", *opts.ContainerId)
		results, err = FindIOCInContainer(scanner)
		if err != nil {
			log.Errorf("error scanning the container: %s", err)
			return
		}
	}

	if results == nil {
		log.Error("set either -local or -image-name flag")
		return
	}

	if len(*opts.ConsoleUrl) != 0 && len(*opts.DeepfenceKey) != 0 {
		pub, err := output.NewPublisher(*opts.ConsoleUrl, strconv.Itoa(*opts.ConsolePort), *opts.DeepfenceKey)
		if err != nil {
			log.Error(err.Error())
		}

		pub.SendReport(output.GetHostname(), *opts.ImageName, *opts.ContainerId, node_type)
		scanId := pub.StartScan(node_id, node_type)
		if len(scanId) == 0 {
			scanId = fmt.Sprintf("%s-%d", node_id, time.Now().UnixMilli())
		}
		pub.IngestSecretScanResults(scanId, results.GetIOC())
		log.Infof("scan id %s", scanId)
	}

	counts := output.CountBySeverity(results.GetIOC())
	log.Infof("result severity counts: %+v", counts)

	fmt.Println("summary:")
	fmt.Printf("  total=%d high=%d medium=%d low=%d\n",
		counts.Total, counts.High, counts.Medium, counts.Low)

	if *opts.OutFormat == "json" {
		err = results.WriteJson()
		if err != nil {
			log.Errorf("error while writing IOC: %s", err)
			return
		}

	} else {
		err = results.WriteTable()
		if err != nil {
			log.Errorf("error while writing IOC: %s", err)
			return
		}
	}

	output.FailOn(counts,
		*opts.FailOnHighCount, *opts.FailOnMediumCount, *opts.FailOnLowCount, *opts.FailOnCount)
}
