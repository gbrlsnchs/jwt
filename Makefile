export GO111MODULE ?= on

all:
	go get golang.org/x/tools/gopls@latest
	go get golang.org/x/tools/cmd/goimports
	go get golang.org/x/lint/golint
	go mod download

fix:
	@goimports -w *.go

lint:
	@! goimports -d . | grep -vF "no errors"
	@golint -set_exit_status ./...
	@go vet

bench:
	@go test -v -run=^$$ -bench=.

test: lint
	@go test ./...
