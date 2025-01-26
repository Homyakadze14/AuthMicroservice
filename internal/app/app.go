package app

import (
	"fmt"
	"log/slog"
	"os"

	grpcapp "github.com/Homyakadze14/AuthMicroservice/internal/app/grpc"
	"github.com/Homyakadze14/AuthMicroservice/internal/config"
	actLinkMailer "github.com/Homyakadze14/AuthMicroservice/internal/lib/mailer"
	"github.com/Homyakadze14/AuthMicroservice/internal/repositories"
	"github.com/Homyakadze14/AuthMicroservice/internal/services"
	"github.com/Homyakadze14/AuthMicroservice/pkg/mailer"
	"github.com/Homyakadze14/AuthMicroservice/pkg/postgres"
)

type App struct {
	db         *postgres.Postgres
	GRPCServer *grpcapp.App
}

func Run(
	log *slog.Logger,
	cfg *config.Config,
) *App {
	// Database
	pg, err := postgres.New(cfg.Database.URL, postgres.MaxPoolSize(cfg.Database.PoolMax))
	if err != nil {
		slog.Error(fmt.Errorf("app - Run - postgres.New: %w", err).Error())
		os.Exit(1)
	}

	// Repository
	accRepo := repositories.NewAccountRepository(pg)
	tokenRepo := repositories.NewTokenRepository(pg)
	linkRepo := repositories.NewLinkRepository(pg)
	pwdLinkRepo := repositories.NewPasswordLinkRepository(pg)

	// Mailer
	mailer := actLinkMailer.New(cfg.BaseLinks, mailer.New(&cfg.Mailer))

	// Services
	auth := services.NewAuthService(log, accRepo, tokenRepo, linkRepo, &cfg.JWTAccess, &cfg.JWTRefresh, mailer, pwdLinkRepo)

	// GRPC
	gRPCServer := grpcapp.New(log, auth, cfg.GRPC.Port)

	return &App{
		db:         pg,
		GRPCServer: gRPCServer,
	}
}

func (s *App) Shutdown() {
	defer s.db.Close()
	defer s.GRPCServer.Stop()
}
