package threatintel

// FeedsBundle represents the structure of the malware rules JSON file
type FeedsBundle struct {
	ScannerFeeds ScannerFeeds `json:"scanner_feeds"`
	Extra        []string     `json:"extra"`
}

type ScannerFeeds struct {
	MalwareRules []DeepfenceRule `json:"malware_rules"`
}

type DeepfenceRule struct {
	RuleID  string `json:"rule_id"`
	Payload string `json:"payload"`
}
