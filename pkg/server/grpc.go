package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/jobs"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
	yararules "github.com/deepfence/YaraHunter/pkg/yararules"
	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	MalwareScanDir = "/"
	HostMountDir   = "/fenced/mnt/host"
)

func init() {
	if os.Getenv("DF_SERVERLESS") == "true" {
		MalwareScanDir = "/"
	} else {
		MalwareScanDir = HostMountDir
	}
}

type gRPCServer struct {
	options     *config.Options
	yaraConfig  *config.Config
	yaraRules   *yararules.YaraRules
	plugin_name string
	pb.UnimplementedMalwareScannerServer
	pb.UnimplementedAgentPluginServer
	pb.UnimplementedScannersServer
}

func (s *gRPCServer) ReportJobsStatus(context.Context, *pb.Empty) (*pb.JobReports, error) {
	return &pb.JobReports{
		RunningJobs: jobs.GetRunningJobCount(),
	}, nil
}

func (s *gRPCServer) GetName(context.Context, *pb.Empty) (*pb.Name, error) {
	return &pb.Name{Str: s.plugin_name}, nil
}

func (s *gRPCServer) GetUID(context.Context, *pb.Empty) (*pb.Uid, error) {
	return &pb.Uid{Str: fmt.Sprintf("%s-%s", s.plugin_name, *s.options.SocketPath)}, nil
}

func (s *gRPCServer) FindMalwareInfo(c context.Context, r *pb.MalwareRequest) (*pb.MalwareResult, error) {
	go func() {
		log.Infof("request to scan %+v", r)

		yaraScanner, err := s.yaraRules.NewScanner()
		scanner := scan.New(s.options, s.yaraConfig, yaraScanner, r.ScanId)
		res := jobs.StartStatusReporter(context.Background(), r.ScanId, scanner)
		defer func() {
			res <- err
			close(res)
		}()

		//Check for error only after the StartStatusReporter as we have to report
		//the error if we failed to create the yara scanner
		if err != nil {
			log.Error("Failed to create Yara Scanner, error:", err)
			return
		}

		var malwares chan output.IOCFound
		trim := false
		if r.GetPath() != "" {
			log.Infof("scan for malwares in path %s", r.GetPath())
			malwares, err = scanner.ScanIOCInDirStream("", "", r.GetPath(), nil, false)
			if err != nil {
				log.Error("finding new err", err)
				return
			}
			trim = true
		} else if r.GetImage() != nil && r.GetImage().Name != "" {
			log.Infof("scan for malwares in image %s", r.GetImage())
			malwares, err = scanner.ExtractAndScanImageStream(r.GetImage().Name)
			if err != nil {
				return
			}
		} else if r.GetContainer() != nil && r.GetContainer().Id != "" {
			log.Infof("scan for malwares in container %s", r.GetContainer())
			malwares, err = scanner.ExtractAndScanContainerStream(r.GetContainer().Id, r.GetContainer().Namespace)
			if err != nil {
				return
			}
			trim = true
		} else {
			err = fmt.Errorf("Invalid request")
			return
		}

		for malware := range malwares {
			if trim {
				malware.CompleteFilename = strings.TrimPrefix(malware.CompleteFilename, HostMountDir)
			}
			output.WriteScanData([]*pb.MalwareInfo{output.MalwaresToMalwareInfo(malware)}, r.GetScanId())
		}
	}()
	return &pb.MalwareResult{}, nil
}

func RunGrpcServer(opts *config.Options, config *config.Config, plugin_name string) error {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	lis, err := net.Listen("unix", fmt.Sprintf("%s", *opts.SocketPath))
	if err != nil {
		return err
	}
	s := grpc.NewServer()

	go func() {
		<-sigs
		s.GracefulStop()
		done <- true
	}()

	impl := &gRPCServer{options: opts, plugin_name: plugin_name, yaraConfig: config}
	if err != nil {
		return err
	}

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
