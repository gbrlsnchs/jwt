install: export GO111MODULE := on
install:
	current_dir := ${PWD}
	@cd ${GOPATH}
	go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.16.0
	go get -u golang.org/x/tools/cmd/goimports

lint: golint_cmd := golint -set_exit_status
lint:
	@echo "+++ 'lint' (${golint_cmd})"
	@${golint_cmd}

test-units: export GO111MODULE := on
test-units: go_test_flags := -v
ifdef GO_TEST_RUN
test-units: go_test_flags += -run=${GO_TEST_RUN}
endif
test-units: GO_TEST_TARGET ?= ./...
test-units: go_test_cmd := go test ${go_test_flags} ${GO_TEST_TARGET}
test-units:
	@echo "+++ 'test-units' (${go_test_cmd})"
	@${go_test_cmd}

test: test-units lint
