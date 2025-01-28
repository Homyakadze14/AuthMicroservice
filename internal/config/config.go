package config

import (
	"flag"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env            string           `yaml:"env" env-default:"local"`
	Database       DatabaseConfig   `yaml:"database"`
	GRPC           GRPCConfig       `yaml:"GRPC"`
	JWTAccess      JWTAccessConfig  `yaml:"jwt_access"`
	JWTRefresh     JWTRefreshConfig `yaml:"jwt_refresh"`
	MigrationsPath string
	Mailer         MailerConfig    `yaml:"mailer"`
	BaseLinks      BaseLinksConfig `yaml:"base_links"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port" env-required:"true"`
	Timeout time.Duration `yaml:"timeout" env-required:"true"`
}

type JWTAccessConfig struct {
	Secret   string        `yaml:"secret" env-required:"true"`
	Duration time.Duration `yaml:"duration" env-required:"true"`
}

type JWTRefreshConfig struct {
	Secret   string        `yaml:"secret" env-required:"true"`
	Duration time.Duration `yaml:"duration" env-required:"true"`
}

type DatabaseConfig struct {
	URL     string `yaml:"url" env:"PG_URL" env-required:"true"`
	PoolMax int    `yaml:"pool_max" env-required:"true"`
}

type MailerConfig struct {
	Username string `yaml:"username" env-required:"true"`
	Password string `yaml:"password" env-required:"true"`
	Host     string `yaml:"host" env-required:"true"`
	Addr     string `yaml:"addr" env-required:"true"`
}

type BaseLinksConfig struct {
	ActivationUrl     string `yaml:"activation_url" env-required:"true"`
	ChangePasswordUrl string `yaml:"change_password_url" env-required:"true"`
}

func MustLoad() *Config {
	configPath := fetchConfigPath()
	if configPath == "" {
		panic("config path is empty")
	}

	return MustLoadPath(configPath)
}

func MustLoadPath(configPath string) *Config {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist: " + configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("cannot read config: " + err.Error())
	}

	return &cfg
}

func fetchConfigPath() string {
	var res string

	flag.StringVar(&res, "config", "", "path to config file")
	flag.Parse()

	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}

	return res
}
