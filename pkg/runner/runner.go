package runner

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
	"github.com/deepfence/YaraHunter/pkg/server"
	"github.com/deepfence/YaraHunter/pkg/yararules"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

type RunnerOptions struct {
	SocketPath                                                      string
	RulesPath                                                       string
	HostMountPath                                                   string
	FailOnCompileWarning                                            bool
	Local                                                           string
	ImageName                                                       string
	ContainerID                                                     string
	ConsoleURL                                                      string
	ConsolePort                                                     int
	DeepfenceKey                                                    string
	OutFormat                                                       string
	FailOnHighCount, FailOnMediumCount, FailOnLowCount, FailOnCount int
	InactiveThreshold                                               int
}

func StartYaraHunter[T any](ctx context.Context,
	opts RunnerOptions,
	config cfg.Config,
	constructServer func(srv *server.GRPCScannerServer) T,
	attachRegistrar func(s grpc.ServiceRegistrar, impl any)) {

	if opts.SocketPath == "" {
		runOnce(ctx, opts, config)
		return
	}

	base, err := server.NewGRPCScannerServer(
		opts.HostMountPath,
		opts.SocketPath,
		opts.RulesPath,
		opts.InactiveThreshold,
		opts.FailOnCompileWarning, config, constants.PluginName,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot init grpc")
	}
	go func() {

		svc := constructServer(base)

		if err := server.RunGrpcServer(ctx,
			opts.SocketPath,
			&svc,
			attachRegistrar,
		); err != nil {
			log.Panic().Err(err).Msg("main: failed to serve")
		}
	}()

	<-ctx.Done()
}

func runOnce(ctx context.Context, opts RunnerOptions, extractorConfig cfg.Config) {
	var results IOCWriter

	yaraRules := yararules.New(opts.RulesPath)
	err := yaraRules.Compile(constants.Filescan, opts.FailOnCompileWarning)
	if err != nil {
		log.Error().Err(err).Msg("error in runOnce compiling yara rules")
		return
	}

	yaraScanner, err := yaraRules.NewScanner()
	if err != nil {
		log.Error().Err(err).Msg("error in runOnce creating yara scanner")
		return
	}

	scanner := scan.New(opts.HostMountPath, extractorConfig, yaraScanner, "")

	outputs := []output.IOCFound{}
	writeToArray := func(res output.IOCFound, scanID string) {
		outputs = append(outputs, res)
	}

	scanCtx := tasks.ScanContext{
		Res:     nil,
		IsAlive: atomic.Bool{},
		Context: ctx,
	}

	var st scan.ScanType
	nodeID := ""
	switch {
	case len(opts.Local) > 0:
		st = scan.DirScan
		nodeID = opts.Local
		log.Info().Str("path", nodeID).Msg("scan for malwares in path")
		err = scanner.Scan(&scanCtx, st, "", opts.Local, "", writeToArray)
		results = &output.JSONDirIOCOutput{DirName: nodeID, IOC: removeDuplicateIOCs(outputs)}
	case len(opts.ImageName) > 0:
		st = scan.ImageScan
		nodeID = opts.ImageName
		log.Info().Str("image", nodeID).Msg("Scanning image for IOC...")
		err = scanner.Scan(&scanCtx, st, "", opts.ImageName, "", writeToArray)
		results = &output.JSONImageIOCOutput{ImageID: nodeID, IOC: removeDuplicateIOCs(outputs)}
	case len(opts.ContainerID) > 0:
		st = scan.ContainerScan
		nodeID = opts.ContainerID
		log.Info().Str("container", nodeID).Msg("scan for malwares in container")
		err = scanner.Scan(&scanCtx, st, "", nodeID, "", writeToArray)
		results = &output.JSONImageIOCOutput{ContainerID: nodeID, IOC: removeDuplicateIOCs(outputs)}
	default:
		err = fmt.Errorf("invalid request")
	}

	results.SetTime()

	if err != nil {
		println(err.Error())
		return
	}

	if len(opts.ConsoleURL) != 0 && len(opts.DeepfenceKey) != 0 {
		pub, err := output.NewPublisher(opts.ConsoleURL, strconv.Itoa(opts.ConsolePort), opts.DeepfenceKey)
		if err != nil {
			log.Error().Err(err).Msg("failed to create publisher")
		}

		pub.SendReport(output.GetHostname(), opts.ImageName, opts.ContainerID, scan.ScanTypeString(st))
		scanID := pub.StartScan(nodeID, scan.ScanTypeString(st))
		if len(scanID) == 0 {
			scanID = fmt.Sprintf("%s-%d", nodeID, time.Now().UnixMilli())
		}
		if err := pub.IngestSecretScanResults(scanID, results.GetIOC()); err != nil {
			log.Error().Err(err).Msg("IngestSecretScanResults failed")
		}
		log.Info().Str("scan_id", scanID).Msg("scan completed")
	}

	counts := output.CountBySeverity(results.GetIOC())

	if opts.OutFormat == "json" {
		log.Info().Interface("counts", counts).Msg("result severity counts")
		err = results.WriteJSON()
		if err != nil {
			log.Error().Err(err).Msg("error while writing IOC")
			return
		}
	} else {
		fmt.Println("summary:")
		fmt.Printf("  total=%d high=%d medium=%d low=%d\n",
			counts.Total, counts.High, counts.Medium, counts.Low)
		err = results.WriteTable()
		if err != nil {
			log.Error().Err(err).Msg("error while writing IOC")
			return
		}
	}

	if results == nil {
		log.Error().Msg("set either -local or -image-name flag")
		return
	}

	output.FailOn(counts,
		opts.FailOnHighCount, opts.FailOnMediumCount, opts.FailOnLowCount, opts.FailOnCount)
}
