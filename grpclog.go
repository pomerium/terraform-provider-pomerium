package main

import (
	"fmt"

	"github.com/rs/zerolog"
)

type grpcLogger struct {
	l zerolog.Logger
}

func (g grpcLogger) Info(args ...any) {
	g.l.Trace().Msg(fmt.Sprint(args...))
}

func (g grpcLogger) Infoln(args ...any) {
	g.l.Trace().Msg(fmt.Sprint(args...))
}

func (g grpcLogger) Infof(format string, args ...any) {
	g.l.Trace().Msgf(format, args...)
}

func (g grpcLogger) Warning(args ...any) {
	g.l.Trace().Msg(fmt.Sprint(args...))
}

func (g grpcLogger) Warningln(args ...any) {
	g.l.Trace().Msg(fmt.Sprint(args...))
}

func (g grpcLogger) Warningf(format string, args ...any) {
	g.l.Trace().Msgf(format, args...)
}

func (g grpcLogger) Error(args ...any) {
	g.l.Trace().Msg(fmt.Sprint(args...))
}

func (g grpcLogger) Errorln(args ...any) {
	g.l.Trace().Msg(fmt.Sprint(args...))
}

func (g grpcLogger) Errorf(format string, args ...any) {
	g.l.Trace().Msgf(format, args...)
}

func (g grpcLogger) Fatal(args ...any) {
	g.l.Trace().Msg(fmt.Sprint(args...))
}

func (g grpcLogger) Fatalln(args ...any) {
	g.l.Trace().Msg(fmt.Sprint(args...))
}

func (g grpcLogger) Fatalf(format string, args ...any) {
	g.l.Trace().Msgf(format, args...)
}

func (g grpcLogger) V(_ int) bool {
	return true
}
