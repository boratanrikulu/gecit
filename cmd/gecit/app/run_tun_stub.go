//go:build (darwin || windows) && !with_gvisor

package app

import (
	"fmt"

	"github.com/boratanrikulu/gecit/pkg/engine"
	"github.com/sirupsen/logrus"
)

func newPlatformEngine(_ engine.Config, _ *logrus.Logger) (engine.Engine, error) {
	return nil, fmt.Errorf("TUN support requires building with -tags with_gvisor")
}
