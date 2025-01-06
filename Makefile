DBURL="postgres://postgres:postgres@localhost:5433/authmicroservice"

gen-proto:
	protoc -I proto proto/**/*.proto --go_out=proto/gen/ --go_opt=paths=source_relative --go-grpc_out=proto/gen/ --go-grpc_opt=paths=source_relative

migrate-up:
	go run cmd/migrator/main.go -storage-url=$(DBURL) -migrations-path=./migrations

migrate-down:
	go run cmd/migrator/main.go -storage-url=$(DBURL) -migrations-path=./migrations -act=d

migrate-force:
	go run cmd/migrator/main.go -storage-url=$(DBURL) -migrations-path=./migrations -fv=1

mock-services:
	cd ./internal/services && mockery --all