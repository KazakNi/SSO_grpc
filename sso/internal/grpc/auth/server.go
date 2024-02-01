package auth

import (
	"context"

	ssov1 "github.com/kazakni/sso_grpc/contracts/gen/go/sso"
	"google.golang.org/grpc"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
}

func Register(gRPC *grpc.Server) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{})
}

func (s *serverAPI) Login(context.Context, *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	panic("implement me!")
}

func (s *serverAPI) Register(context.Context, *ssov1.RegisterRequest,
) (ssov1.RegisterRequest, error) {
	panic("implement me!")
}

func (s *serverAPI) IsAdmin(
	context.Context,
	*ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	panic("implement me!")
}
