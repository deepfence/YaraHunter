package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
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
	options    *config.Options
	yaraConfig *config.Config
	yaraRules  *yararules.YaraRules
	pluginName string
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
		scanner := scan.New(s.options, s.yaraConfig, yaraScanner, r.ScanId)
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

		var malwares chan output.IOCFound
		trim := false
		isContainer := false
		switch {
		case r.GetPath() != "":
			log.Infof("scan for malwares in path %s", r.GetPath())
			malwares, err = scanner.ScanIOCInDirStream("", "", r.GetPath(), nil, false, ctx)
			if err != nil {
				log.Error("finding new err", err)
				return
			}
			trim = true
		case r.GetImage() != nil && r.GetImage().Name != "":
			log.Infof("scan for malwares in image %s", r.GetImage())
			malwares, err = scanner.ExtractAndScanImageStream(ctx, r.GetImage().Name)
			if err != nil {
				return
			}
		case r.GetContainer() != nil && r.GetContainer().Id != "":
			log.Infof("scan for malwares in container %s", r.GetContainer())
			malwares, err = scanner.ExtractAndScanContainerStream(ctx, r.GetContainer().Id, r.GetContainer().Namespace)
			if err != nil {
				return
			}
			isContainer = true
			trim = true
		default:
			err = fmt.Errorf("invalid request")
			return

		}

		for malware := range malwares {
			if isContainer {
				ret := cntnrPathPrefixRegexObj.FindStringSubmatchIndex(malware.CompleteFilename)
				if ret != nil {
					malware.CompleteFilename = malware.CompleteFilename[ret[1]-1:]
				}
			} else if trim {
				malware.CompleteFilename = strings.TrimPrefix(malware.CompleteFilename, HostMountDir)
			}

			output.WriteScanData([]*pb.MalwareInfo{output.MalwaresToMalwareInfo(malware)}, r.GetScanId())
		}
	}()
	return &pb.MalwareResult{}, nil
}

func RunGrpcServer(opts *config.Options, config *config.Config, pluginName string) error {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	lis, err := net.Listen("unix", *opts.SocketPath)
	if err != nil {
		return err
	}
	s := grpc.NewServer()

	go func() {
		<-sigs
		s.GracefulStop()
		done <- true
	}()

	impl := &gRPCServer{options: opts, pluginName: pluginName, yaraConfig: config}
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
	if err := s.Serve(lis); err != nil {
		return err
	}

	<-done
	log.Info("main: exiting gracefully")
	return nil
}
