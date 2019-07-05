export GO111MODULE ?= on
GO_COMMAND ?= go

all: export GO111MODULE := off
all:
	go get -u golang.org/x/tools/cmd/goimports
	go get -u golang.org/x/lint/golint
ifeq (${GO_COMMAND},vgo)
	go get -u golang.org/x/vgo
endif

fix:
	@goimports -w *.go

lint:
	@! goimports -d . | grep -vF "no errors"
	@golint -set_exit_status ./...

bench:
	@${GO_COMMAND} test -v -run=^$$ -bench=.

ifeq (${GO_COMMAND},vgo)
undefine GO111MODULE
endif
test: lint
	@${GO_COMMAND} test -v ./...
