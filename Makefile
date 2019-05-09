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
test-units: go_test_flags := -v -coverprofile=c.out
ifdef GO_TEST_RUN
test-units: go_test_flags += -run=${GO_TEST_RUN}
endif
test-units: GO_TEST_TARGET ?= ./...
test-units: go_test_cmd := go test ${go_test_flags} ${GO_TEST_TARGET}
test-units:
	@echo "+++ 'test-units' (${go_test_cmd})"
	@${go_test_cmd}

test-cover: export GO111MODULE := on
test-cover: go_tool_cover := go tool cover -func=c.out
test-cover:
	@echo "+++ 'test-cover' (${go_tool_cover})"
	@${go_tool_cover}

test: test-units lint
