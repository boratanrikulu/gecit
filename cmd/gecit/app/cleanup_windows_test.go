package app

import "testing"

func TestStaleRouteDeleteCommandsForDefaultRoute(t *testing.T) {
	routePrint := `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0        10.8.32.1      10.8.46.188     40
          0.0.0.0          0.0.0.0        10.0.85.2        10.0.85.1      0
`

	cmds := staleRouteDeleteCommands(routePrint)
	if len(cmds) == 0 {
		t.Fatal("staleRouteDeleteCommands returned no commands for stale gecit default route")
	}

	foundDefaultDelete := false
	for _, cmd := range cmds {
		if len(cmd) >= 6 && cmd[0] == "route" && cmd[1] == "delete" && cmd[2] == "0.0.0.0" && cmd[5] == "10.0.85.2" {
			foundDefaultDelete = true
			break
		}
	}
	if !foundDefaultDelete {
		t.Fatal("staleRouteDeleteCommands missing default route delete for 10.0.85.2")
	}
}

func TestStaleRouteDeleteCommandsForCleanRoutes(t *testing.T) {
	routePrint := `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0        10.8.32.1      10.8.46.188     40
`

	cmds := staleRouteDeleteCommands(routePrint)
	if len(cmds) != 0 {
		t.Fatalf("staleRouteDeleteCommands returned %d commands for clean route table, want 0", len(cmds))
	}
}
