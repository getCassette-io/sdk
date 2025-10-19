package utils

import (
	"log"
	"testing"
)

type TestWriter struct {
	t *testing.T
}

func (l *TestWriter) Write(p []byte) (n int, err error) {
	l.t.Log(string(p))
	return len(p), nil
}

func NewTestLogger(t *testing.T) *log.Logger {
	return log.New(&TestWriter{t: t}, "", 0)
}
