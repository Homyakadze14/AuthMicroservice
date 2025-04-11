DBURL=postgres://postgres:postgres@localhost:5433/authmicroservice

gen-proto:
	protoc -I proto proto/$(pkg)/*.proto --go_out=proto/gen/ --go_opt=paths=source_relative --go-grpc_out=proto/gen/ --go-grpc_opt=paths=source_relative

gen-docs:
	swag init -g=internal/controller/rest/v1/router.go -o=docs --parseInternal

mock-services:
	cd ./internal/services && mockery --all

migration-up:
	migrate -path migrations -database '${DBURL}?sslmode=disable' up ${v}

migration-down:
	migrate -path migrations -database '${DBURL}?sslmode=disable' down ${v}

migration-fix:
	migrate -database "${DBURL}" -path migrations force ${v}