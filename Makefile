export GO111MODULE := on
GO_COMMAND ?= go

all: export GO111MODULE := off
all:
	go get -u golang.org/x/tools/cmd/goimports
	go get -u golang.org/x/lint/golint

fix:
	@goimports -w *.go

lint:
	@! goimports -d . | grep -vF "no errors"
	@golint -set_exit_status ./...

bench:
	@${GO_COMMAND} test -v -run=^$$ -bench=.

test: lint
	@${GO_COMMAND} test -v ./...
