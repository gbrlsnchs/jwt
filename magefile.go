// +build mage

package main

import (
	"runtime"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const (
	goimportsCmd = "goimports"
	golintCmd    = "golint"

	// Dependencies.
	ed25519Dep = "golang.org/x/crypto/ed25519"
	xerrorsDep = "golang.org/x/xerrors"

	goplsImportPath     = "golang.org/x/tools/gopls"
	goimportsImportPath = "golang.org/x/tools/cmd/goimports"
	golintImportPath    = "golang.org/x/lint/golint"
)

var (
	goCmd     = mg.GoCmd()
	goVersion = runtime.Version()
)

// Fix runs "goimports" to fix all files.
func Fix() error {
	return sh.Run(goimportsCmd, "-w", ".")
}

// Install installs all development dependencies.
func Install() error {
	switch goVersion {
	case "go1.9.7", "go1.10.3":
		return installWithGoGet()
	default:
		return installWithModules()
	}
}

// Lint lints using "golint" and "goimports".
func Lint() error {
	linters := [][]string{
		[]string{goimportsCmd, "-d", "."},
		[]string{golintCmd, "-set_exit_status", "./..."},
	}
	for _, linter := range linters {
		if err := sh.Run(linter[0], linter[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// Test tests using "go test".
func Test() error {
	return sh.Run(goCmd, "test", "./...")
}

func installWithModules() error {
	deps := []string{
		goplsImportPath,
		goimportsImportPath,
		golintImportPath,
	}
	for _, dep := range deps {
		if err := sh.Run(goCmd, "install", dep); err != nil {
			return err
		}
	}
	return nil
}

func installWithGoGet() error {
	deps := []string{
		ed25519Dep,
		xerrorsDep,
		goplsImportPath,
		goimportsImportPath,
		golintImportPath,
	}
	for _, dep := range deps {
		if err := sh.Run(goCmd, "get", "-u", dep); err != nil {
			return err
		}
	}
	return nil
}
