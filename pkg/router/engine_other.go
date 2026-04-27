//go:build !linux

package router

import (
	"context"

	"github.com/sirupsen/logrus"
)

func defaultRunnerFactory(cfg Config, logger *logrus.Logger) (lifecycleRunner, error) {
	return nil, ErrRouterUnsupported
}

func defaultBatchApplier(ctx context.Context, batch string) error {
	return ErrRouterUnsupported
}
