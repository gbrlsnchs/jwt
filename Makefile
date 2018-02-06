BIN=go
FLAGS=-v -race
DEP=dep
DEP_BKP=vendor.orig
EXCLUDE=$(shell find . -type f -name '*.go' -not -path './vendor/*')
IMPORT_BIN=goimports
IMPORT_FLAGS=-l
IMPORT=$(shell $(IMPORT_BIN) $(IMPORT_FLAGS) $(EXCLUDE))

all: test

test: distclean import
	$(BIN) test $(FLAGS) ./...

distclean:
	rm -f $(DEP_BKP)

import:
ifneq (,$(IMPORT))
	$(error $(shell $(IMPORT_BIN) -d))
endif

install: goimports dep
ifeq (,$(wildcard Gopkg.*))
	$(DEP) init
endif
	$(DEP) ensure

goimports:
	$(BIN) get golang.org/x/tools/cmd/goimports

dep:
	$(BIN) get -u github.com/golang/dep/cmd/dep
