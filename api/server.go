//go:generate protoc -I ./flows ./proto/flows.proto --go_out=plugins=grpc:api

package api

import (
	"context"
	"net"

	"golang.org/x/xerrors"
	"google.golang.org/grpc"

	pb "github.com/yuuki/shawk/api/proto/"
	"github.com/yuuki/shawk/logging"
)

const (
	port = ":50051"
)

var logger = logging.New("api")

// server is used to implement Users.UsersServer.
type server struct{}

// GetFlowsRequest implements proto.FlowsServer
func (s *server) GetFlows(ctx context.Context, in *pb.GetFlowsRequest) (*pb.FlowsResponse, error) {
	logger.Debugf("Received: %v", in.Name)
	return &pb.FlowsResponse{Message: "Hello " + in.Name}, nil
}

// Serve kicks API server.
func Serve() error {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		xerrors.Errorf("Could not listen: %w", err)
	}
	s := grpc.NewServer()
	pb.RegisterFlowServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		xerrors.Errorf("Could not serve: %w", err)
	}
}
