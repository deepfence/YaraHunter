package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deepfence/YaRadare/core"
	"github.com/deepfence/YaRadare/output"
	"github.com/deepfence/YaRadare/scan"
	pb "github.com/deepfence/agent-plugins-grpc/proto"
	"google.golang.org/grpc"
)

type gRPCServer struct {
	socket_path string
	plugin_name string
	pb.UnimplementedMalwareScannerServer
	pb.UnimplementedAgentPluginServer
}

func (s *gRPCServer) GetName(context.Context, *pb.Empty) (*pb.Name, error) {
	return &pb.Name { Str: s.plugin_name }, nil
}

func (s *gRPCServer) GetUID(context.Context, *pb.Empty) (*pb.Uid, error) {
	return &pb.Uid { Str: fmt.Sprintf("%s-%s", s.plugin_name, s.socket_path) }, nil
}

func (s *gRPCServer) FindMalwareInfo(_ context.Context, r *pb.MalwareRequest) (*pb.MalwareResult, error) {
	if r.GetPath()  != "" {
		var malwares []output.IOCFound
	    err := scan.ScanIOCInDir("", "", r.GetPath(), nil, &malwares, false)
		if err != nil {
			return nil, err
		}
		return &pb.MalwareResult{
			Timestamp: time.Now().String(),
			Malwares: output.MalwaresToMalwareInfos(malwares),
			Input: &pb.MalwareResult_Path{
				Path: r.GetPath(),
			},
		}, nil
	} else if r.GetImage() != nil && r.GetImage().Name != "" {
		res, err := scan.ExtractAndScanImage(r.GetImage().Name)
		if err != nil {
			return nil, err
		}

		return &pb.MalwareResult{
			Timestamp: time.Now().String(),
			Malwares: output.MalwaresToMalwareInfos(res.IOCs),
			Input: &pb.MalwareResult_Image{
				Image: &pb.MalwareDockerImage{
					Name: r.GetImage().Name,
					Id: res.ImageId,
				},
			},
		}, nil
	} else if r.GetContainer() != nil && r.GetContainer().Id != "" {
		var malwares []output.IOCFound
		malwares, err := scan.ExtractAndScanContainer(r.GetContainer().Id, r.GetContainer().Namespace)
		if err != nil {
			return nil, err
		}

		return &pb.MalwareResult{
			Timestamp: time.Now().String(),
			Malwares: output.MalwaresToMalwareInfos(malwares),
			Input: &pb.MalwareResult_Container{
				Container: &pb.MalwareContainer{
					Namespace: r.GetContainer().Namespace,
					Id: r.GetContainer().Id,
				},
			},
		}, nil
	}
	return nil, fmt.Errorf("Invalid request")
}

func RunServer(socket_path string, plugin_name string) error {

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	lis, err := net.Listen("unix", fmt.Sprintf("%s", socket_path))
	if err != nil {
		return err
	}
	s := grpc.NewServer()

	go func() {
		<-sigs
		s.GracefulStop()
		done <- true
	}()
	impl := &gRPCServer{socket_path: socket_path, plugin_name: plugin_name}
	pb.RegisterAgentPluginServer(s, impl)
	pb.RegisterMalwareScannerServer(s, impl)
	core.GetSession().Log.Info("main: server listening at %v", lis.Addr())
	fmt.Print("main: server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		return err
	}

	<-done
	core.GetSession().Log.Info("main: exiting gracefully")
	return nil
}
