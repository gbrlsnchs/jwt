package internal

import "golang.org/x/xerrors"

// Errorf is a wrapper for xerrors.Errorf.
func Errorf(format string, a ...interface{}) error { return xerrors.Errorf(format, a...) }

// ErrorAs is a wrapper for xerrors.As.
func ErrorAs(err error, target interface{}) bool { return xerrors.As(err, target) }

// ErrorIs is a wrapper for xerrors.Is.
func ErrorIs(err, target error) bool { return xerrors.Is(err, target) }

// NewError is a wrapper for xerrors.New.
func NewError(text string) error { return xerrors.New(text) }
