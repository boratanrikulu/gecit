//go:build (darwin || windows) && !with_gvisor

package app

import (
	"fmt"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/sirupsen/logrus"
)

func newPlatformEngine(cfg engine.Config, logger *logrus.Logger) (engine.Engine, error) {
	return nil, fmt.Errorf("TUN engine requires build tag with_gvisor")
}
