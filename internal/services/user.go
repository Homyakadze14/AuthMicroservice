package services

import (
	"fmt"
	"log/slog"

	"github.com/Homyakadze14/AuthMicroservice/internal/config"
	userv1 "github.com/Homyakadze14/AuthMicroservice/proto/gen/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type UserService struct {
	log *slog.Logger

	cfg  config.UserServiceConfig
	conn *grpc.ClientConn
}

func NewUserService(log *slog.Logger, cfg config.UserServiceConfig) *UserService {
	return &UserService{
		log: log,
		cfg: cfg,
	}
}

func (s *UserService) Connect() userv1.UserClient {
	const op = "UserService.Connect"

	log := s.log.With(
		slog.String("op", op),
	)

	log.Info("trying to connect to user service")
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	conn, err := grpc.NewClient(s.cfg.Addr, opts...)
	if err != nil {
		log.Error("failed to connect to user service")
		panic(fmt.Errorf("%s: %w", op, err))
	}
	s.conn = conn

	client := userv1.NewUserClient(conn)
	log.Info("successfully connected to the user service")

	return client
}

func (s *UserService) CloseConn() error {
	if s.conn != nil {
		err := s.conn.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
