//go:build linux

package router

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

func defaultRunnerFactory(cfg Config, logger *logrus.Logger) (lifecycleRunner, error) {
	return newNFQRunner(cfg, logger)
}

func defaultBatchApplier(ctx context.Context, batch string) error {
	if strings.TrimSpace(batch) == "" {
		return nil
	}

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return fmt.Errorf("nft -f -: %w", err)
	}
	return fmt.Errorf("nft -f -: %s: %w", msg, err)
}
