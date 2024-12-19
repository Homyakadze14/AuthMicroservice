package main

import (
	"errors"
	"flag"
	"fmt"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	var storagePath, migrationsPath, migrationsTable, action, force string

	flag.StringVar(&storagePath, "storage-url", "", "path to storage")
	flag.StringVar(&migrationsPath, "migrations-path", "", "path to migrations")
	flag.StringVar(&migrationsTable, "migrations-table", "migrations", "name of migrations table")
	flag.StringVar(&action, "act", "u", "Migrate Up or Down. Enter u or d")
	flag.StringVar(&force, "fv", "", "force migration to version")
	flag.Parse()

	if storagePath == "" {
		panic("storage-path is required")
	}
	if migrationsPath == "" {
		panic("migrations-path is required")
	}

	if action != "u" && action != "d" {
		panic("migrations action must be u or d!")
	}

	m, err := migrate.New(
		"file://"+migrationsPath,
		fmt.Sprintf("%s?x-migrations-table=%s&sslmode=disable", storagePath, migrationsTable),
	)
	if err != nil {
		panic(err)
	}

	if force != "" {
		v, err := strconv.Atoi(force)
		if err != nil {
			panic("Force version must be integer!")
		}

		err = m.Force(v)
	} else if action == "u" {
		err = m.Up()
	} else if action == "d" {
		err = m.Down()
	}

	defer m.Close()
	if err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("no migrations to apply")

			return
		}

		panic(err)
	}

	fmt.Println("Migrate successfully")
}
