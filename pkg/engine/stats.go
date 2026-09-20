package engine

// Stats is the engine's live counter set. Each manager fills the fields it
// owns and the engine merges them, so a field a manager does not count stays
// zero rather than being reported by two places at once.
type Stats struct {
	// Connections counts connections on a target port that gecit intercepted.
	Connections   uint64 `json:"connections"`
	FakesInjected uint64 `json:"fakes_injected"`
	InjectErrors  uint64 `json:"inject_errors"`
	DNSQueries    uint64 `json:"dns_queries"`
	DNSErrors     uint64 `json:"dns_errors"`
}
