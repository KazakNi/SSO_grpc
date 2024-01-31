package auth

import (
	ssov1 "github.com/kazakni/sso_grpc/contracts/gen/go/sso"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
}
