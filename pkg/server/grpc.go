package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/jobs"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
	yararules "github.com/deepfence/YaraHunter/pkg/yararules"
	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
	tasks "github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	cfg "github.com/deepfence/match-scanner/pkg/config"
)

var (
	MalwareScanDir          = "/"
	HostMountDir            = "/fenced/mnt/host"
	cntnrPathPrefixRegex    = `.+?\/overlay2\/[A-z0-9a-z]+\/[a-z]+\/`
	cntnrPathPrefixRegexObj *regexp.Regexp
)

func init() {
	if os.Getenv("DF_SERVERLESS") == "true" {
		MalwareScanDir = "/"
	} else {
		MalwareScanDir = HostMountDir
	}
	cntnrPathPrefixRegexObj = regexp.MustCompile(cntnrPathPrefixRegex)
}

type gRPCServer struct {
	options         *config.Options
	extractorConfig cfg.Config
	yaraRules       *yararules.YaraRules
	pluginName      string
	pb.UnimplementedMalwareScannerServer
	pb.UnimplementedAgentPluginServer
	pb.UnimplementedScannersServer

	scanMap sync.Map
}

func (s *gRPCServer) ReportJobsStatus(context.Context, *pb.Empty) (*pb.JobReports, error) {
	return &pb.JobReports{
		RunningJobs: jobs.GetRunningJobCount(),
	}, nil
}

func (s *gRPCServer) StopScan(c context.Context, req *pb.StopScanRequest) (*pb.StopScanResult, error) {
	scanID := req.ScanId
	result := &pb.StopScanResult{
		Success:     true,
		Description: "",
	}

	obj, found := s.scanMap.Load(scanID)
	if !found {
		msg := "Failed to Stop scan"
		log.Infof("%s, may have already completed, scan_id: %s", msg, scanID)
		result.Success = false
		result.Description = "Failed to Stop scan"
		return result, nil
	} else {
		msg := "Stop request submitted"
		log.Infof("%s, scan_id: %s", msg, scanID)
		result.Success = true
		result.Description = msg
	}

	scanContext := obj.(*tasks.ScanContext)
	scanContext.StopTriggered.Store(true)
	scanContext.Cancel()

	return result, nil
}

func (s *gRPCServer) GetName(context.Context, *pb.Empty) (*pb.Name, error) {
	return &pb.Name{Str: s.pluginName}, nil
}

func (s *gRPCServer) GetUID(context.Context, *pb.Empty) (*pb.Uid, error) {
	return &pb.Uid{Str: fmt.Sprintf("%s-%s", s.pluginName, *s.options.SocketPath)}, nil
}

func (s *gRPCServer) FindMalwareInfo(c context.Context, r *pb.MalwareRequest) (*pb.MalwareResult, error) {
	go func() {
		log.Infof("request to scan %+v", r)

		jobs.StartScanJob()
		defer jobs.StopScanJob()

		yaraScanner, err := s.yaraRules.NewScanner()
		scanner := scan.New(s.options, s.extractorConfig, yaraScanner, r.ScanId)
		res, ctx := tasks.StartStatusReporter(
			r.ScanId,
			func(status tasks.ScanStatus) error {
				output.WriteScanStatus(status.ScanStatus, status.ScanId, status.ScanMessage)
				return nil
			},
			tasks.StatusValues{
				IN_PROGRESS: "IN_PROGRESS",
				CANCELLED:   "CANCELLED",
				FAILED:      "ERROR",
				SUCCESS:     "COMPLETE",
			},
			time.Duration(*s.options.InactiveThreshold)*time.Second)
		s.scanMap.Store(scanner.ScanID, ctx)
		defer func() {
			s.scanMap.Delete(scanner.ScanID)
			res <- err
			close(res)
		}()

		// Check for error only after the StartStatusReporter as we have to report
		// the error if we failed to create the yara scanner
		if err != nil {
			log.Error("Failed to create Yara Scanner, error:", err)
			return
		}
		writeToFile := func(res output.IOCFound, scanID string) {
			output.WriteScanData([]*pb.MalwareInfo{output.MalwaresToMalwareInfo(res)}, scanID)
		}
		switch {
		case r.GetPath() != "":
			log.Infof("scan for malwares in path %s", r.GetPath())
			err = scanner.Scan(ctx, scan.DirScan, "", r.GetPath(), r.GetScanId(), writeToFile)
		case r.GetImage() != nil && r.GetImage().Name != "":
			log.Infof("scan for malwares in image %s", r.GetImage())
			err = scanner.Scan(ctx, scan.ImageScan, "", r.GetImage().Name, r.GetScanId(), writeToFile)
		case r.GetContainer() != nil && r.GetContainer().Id != "":
			log.Infof("scan for malwares in container %s", r.GetContainer())
			err = scanner.Scan(ctx, scan.ContainerScan, r.GetContainer().Namespace, r.GetContainer().Id, r.GetScanId(), writeToFile)
		default:
			err = fmt.Errorf("invalid request")
		}

		if err != nil {
			println(err.Error())
		}
	}()
	return &pb.MalwareResult{}, nil
}

func RunGrpcServer(ctx context.Context, opts *config.Options, config cfg.Config, pluginName string) error {

	lis, err := net.Listen("unix", *opts.SocketPath)
	if err != nil {
		return err
	}
	s := grpc.NewServer()

	impl := &gRPCServer{options: opts, pluginName: pluginName, extractorConfig: config}
	if err != nil {
		return err
	}

	impl.scanMap = sync.Map{}

	// compile yara rules
	impl.yaraRules = yararules.New(*opts.RulesPath)
	err = impl.yaraRules.Compile(constants.Filescan, *opts.FailOnCompileWarning)
	if err != nil {
		return err
	}

	pb.RegisterAgentPluginServer(s, impl)
	pb.RegisterMalwareScannerServer(s, impl)
	pb.RegisterScannersServer(s, impl)
	log.Info("main: server listening at ", lis.Addr())
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Errorf("server: %v", err)
		}
	}()

	<-ctx.Done()
	s.GracefulStop()

	log.Info("main: exiting gracefully")
	return nil
}
