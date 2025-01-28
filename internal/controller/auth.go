package controller

import (
	"context"
	"errors"

	"github.com/Homyakadze14/AuthMicroservice/internal/entities"
	"github.com/Homyakadze14/AuthMicroservice/internal/lib/jwt"
	"github.com/Homyakadze14/AuthMicroservice/internal/services"
	authv1 "github.com/Homyakadze14/AuthMicroservice/proto/gen/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serverAPI struct {
	authv1.UnimplementedAuthServer
	auth Auth
}

type Auth interface {
	Login(ctx context.Context, acc *entities.Account) (*entities.TokenPair, error)
	Register(ctx context.Context, acc *entities.Account) error
	Logout(ctx context.Context, tok *entities.LogoutRequest) error
	ActivateAccount(ctx context.Context, link string) error
	Refresh(ctx context.Context, refreshToken string) (*entities.TokenPair, error)
	Verify(ctx context.Context, accToken string) (bool, error)
	SendPwdLink(ctx context.Context, email string) (bool, error)
	ChangePwd(ctx context.Context, link *entities.ChPwdLink) (bool, error)
}

func Register(gRPCServer *grpc.Server, auth Auth) {
	authv1.RegisterAuthServer(gRPCServer, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(
	ctx context.Context,
	in *authv1.LoginRequest,
) (*authv1.LoginResponse, error) {
	if in.Username == "" && in.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "username or email is required")
	}

	if in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	data := &entities.Account{
		Username: in.Username,
		Email:    in.Email,
		Password: in.Password,
	}
	tokenPair, err := s.auth.Login(ctx, data)
	if err != nil {
		if errors.Is(err, services.ErrBadCredentials) || errors.Is(err, services.ErrAccountNotFound) {
			return nil, status.Error(codes.InvalidArgument, "invalid email, username or password")
		}

		if errors.Is(err, services.ErrNotActivated) {
			return nil, status.Error(codes.Unauthenticated, "account not activated")
		}

		return nil, status.Error(codes.Internal, "failed to login")
	}

	return &authv1.LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	}, nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	in *authv1.RegisterRequest,
) (*authv1.RegisterResponse, error) {
	if in.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}

	if in.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	data := &entities.Account{
		Username: in.Username,
		Email:    in.Email,
		Password: in.Password,
	}
	err := s.auth.Register(ctx, data)
	if err != nil {
		if errors.Is(err, services.ErrAccountAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "account already exists")
		}

		return nil, status.Error(codes.Internal, "failed to register")
	}

	return &authv1.RegisterResponse{Success: true}, nil
}

func (s *serverAPI) Logout(
	ctx context.Context,
	in *authv1.LogoutRequest,
) (*authv1.LogoutResponse, error) {
	if in.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	data := &entities.LogoutRequest{
		RefreshToken: in.RefreshToken,
	}
	err := s.auth.Logout(ctx, data)
	if err != nil {
		if errors.Is(err, services.ErrTokenNotFound) {
			return nil, status.Error(codes.NotFound, "token not found")
		}

		return nil, status.Error(codes.Internal, "failed to logout")
	}

	return &authv1.LogoutResponse{Success: true}, nil
}

func (s *serverAPI) ActivateAccount(
	ctx context.Context,
	in *authv1.ActivateAccountRequest,
) (*authv1.ActivateAccountResponse, error) {
	if in.Link == "" {
		return nil, status.Error(codes.InvalidArgument, "link is required")
	}

	err := s.auth.ActivateAccount(ctx, in.Link)
	if err != nil {
		if errors.Is(err, services.ErrLinkNotFound) {
			return nil, status.Error(codes.NotFound, "link not found")
		}

		return nil, status.Error(codes.Internal, "failed to activate account")
	}

	return &authv1.ActivateAccountResponse{Success: true}, nil
}

func (s *serverAPI) Refresh(
	ctx context.Context,
	in *authv1.RefreshRequest,
) (*authv1.RefreshResponse, error) {
	if in.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	tokenPair, err := s.auth.Refresh(ctx, in.RefreshToken)
	if err != nil {
		if errors.Is(err, services.ErrAccountNotFound) {
			return nil, status.Error(codes.NotFound, "account not found")
		}
		if errors.Is(err, services.ErrTokenNotFound) {
			return nil, status.Error(codes.NotFound, "token not found")
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, status.Error(codes.Unauthenticated, "token expired")
		}

		return nil, status.Error(codes.Internal, "failed to refresh")
	}

	return &authv1.RefreshResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	}, nil
}

func (s *serverAPI) Verify(
	ctx context.Context,
	in *authv1.VerifyRequest,
) (*authv1.VerifyResponse, error) {
	if in.AccessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access token is required")
	}

	verified, err := s.auth.Verify(ctx, in.AccessToken)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, status.Error(codes.Unauthenticated, "token expired")
		}
		if errors.Is(err, jwt.ErrBadToken) {
			return nil, status.Error(codes.InvalidArgument, "bad token")
		}
		return nil, status.Error(codes.Internal, "failed to verify")
	}

	return &authv1.VerifyResponse{Verified: verified}, nil
}

func (s *serverAPI) SendPasswordLink(
	ctx context.Context,
	in *authv1.SendPasswordLinkRequest,
) (*authv1.SendPasswordLinkResponse, error) {
	if in.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	success, err := s.auth.SendPwdLink(ctx, in.Email)
	if err != nil {
		if errors.Is(err, services.ErrAccountNotFound) {
			return nil, status.Error(codes.NotFound, "account not found")
		}
		return nil, status.Error(codes.Internal, "failed to send password link")
	}

	return &authv1.SendPasswordLinkResponse{Success: success}, nil
}

func (s *serverAPI) ChangePassword(
	ctx context.Context,
	in *authv1.ChangePasswordRequest,
) (*authv1.ChangePasswordResponse, error) {
	if in.Link == "" || in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "link and password is required")
	}

	link := &entities.ChPwdLink{
		Link:     in.Link,
		Password: in.Password,
	}

	success, err := s.auth.ChangePwd(ctx, link)
	if err != nil {
		if errors.Is(err, services.ErrLinkNotFound) {
			return nil, status.Error(codes.NotFound, "link not found")
		}
		return nil, status.Error(codes.Internal, "failed to change password")
	}

	return &authv1.ChangePasswordResponse{Success: success}, nil
}
