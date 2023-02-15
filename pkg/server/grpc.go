package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
	yararules "github.com/deepfence/YaraHunter/pkg/yararules"
	pb "github.com/deepfence/agent-plugins-grpc/proto"
	yara "github.com/hillu/go-yara/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type gRPCServer struct {
	options     *config.Options
	yaraConfig  *config.Config
	yaraRules   *yara.Rules
	plugin_name string
	pb.UnimplementedMalwareScannerServer
	pb.UnimplementedAgentPluginServer
}

func (s *gRPCServer) GetName(context.Context, *pb.Empty) (*pb.Name, error) {
	return &pb.Name{Str: s.plugin_name}, nil
}

func (s *gRPCServer) GetUID(context.Context, *pb.Empty) (*pb.Uid, error) {
	return &pb.Uid{Str: fmt.Sprintf("%s-%s", s.plugin_name, *s.options.SocketPath)}, nil
}

func (s *gRPCServer) FindMalwareInfo(_ context.Context, r *pb.MalwareRequest) (*pb.MalwareResult, error) {
	scanner, err := scan.New(s.options, s.yaraConfig, s.yaraRules)
	if err != nil {
		return nil, err
	}
	scanner.SetImageName(r.GetImage().Name)
	if r.GetPath() != "" {
		var malwares []output.IOCFound
		//log.Error("find malwares", malwares)
		err := scanner.ScanIOCInDir("", "", r.GetPath(), nil, &malwares, false)
		if err != nil {
			log.Error("finding new err", err)
			return nil, err
		}
		return &pb.MalwareResult{
			Timestamp: time.Now().String(),
			Malwares:  output.MalwaresToMalwareInfos(malwares),
			Input: &pb.MalwareResult_Path{
				Path: r.GetPath(),
			},
		}, nil
	} else if r.GetImage() != nil && r.GetImage().Name != "" {
		res, err := scanner.ExtractAndScanImage()
		if err != nil {
			return nil, err
		}

		return &pb.MalwareResult{
			Timestamp: time.Now().String(),
			Malwares:  output.MalwaresToMalwareInfos(res.IOCs),
			Input: &pb.MalwareResult_Image{
				Image: &pb.MalwareDockerImage{
					Name: r.GetImage().Name,
					Id:   res.ImageId,
				},
			},
		}, nil
	} else if r.GetContainer() != nil && r.GetContainer().Id != "" {
		var malwares []output.IOCFound
		malwares, err := scanner.ExtractAndScanContainer(r.GetContainer().Id, r.GetContainer().Namespace)
		if err != nil {
			return nil, err
		}

		return &pb.MalwareResult{
			Timestamp: time.Now().String(),
			Malwares:  output.MalwaresToMalwareInfos(malwares),
			Input: &pb.MalwareResult_Container{
				Container: &pb.MalwareContainer{
					Namespace: r.GetContainer().Namespace,
					Id:        r.GetContainer().Id,
				},
			},
		}, nil
	}
	return nil, fmt.Errorf("Invalid request")
}

func RunServer(opts *config.Options, plugin_name string) error {
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

	impl := &gRPCServer{options: opts, plugin_name: plugin_name}
	if err != nil {
		return err
	}
	// compile yara rules
	impl.yaraRules, err = yararules.New(*opts.RulesPath).Compile(constants.Filescan, *opts.FailOnCompileWarning)
	if err != nil {
		return err
	}
	pb.RegisterAgentPluginServer(s, impl)
	pb.RegisterMalwareScannerServer(s, impl)
	log.Info("main: server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		return err
	}

	<-done
	log.Info("main: exiting gracefully")
	return nil
}
