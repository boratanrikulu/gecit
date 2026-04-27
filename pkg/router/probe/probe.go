package probe

// Candidate describes one strategy the blockcheck-style probe can test.
type Candidate struct {
	Name            string
	TCP             bool
	UDP             bool
	RequiresPostNAT bool
	Notes           string
}

// Plan describes the minimal state needed to probe router-mode candidates.
type Plan struct {
	QueueNum   uint16
	Targets    []string
	Candidates []Candidate
}

// Result captures the outcome of a single candidate against a single target.
type Result struct {
	Target    string
	Candidate string
	Success   bool
	Notes     string
}

// DefaultPlan starts with a single conservative TCP candidate and leaves UDP opt-in.
func DefaultPlan() Plan {
	return Plan{
		QueueNum: 200,
		Targets:  []string{"discord.com", "youtube.com"},
		Candidates: []Candidate{
			{
				Name:            "tcp-fake-clienthello-low-ttl",
				TCP:             true,
				UDP:             false,
				RequiresPostNAT: true,
				Notes:           "Baseline TCP desync candidate for router mode.",
			},
		},
	}
}
