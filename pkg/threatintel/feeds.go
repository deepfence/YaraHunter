package threatintel

type FeedsBundle struct {
	Version      string       `json:"version"`
	CreatedAt    int64        `json:"created_at"`
	ScannerFeeds ScannerFeeds `json:"scanner_feeds"`
	TracerFeeds  TracerFeeds  `json:"tracer_feeds"`
	Extra        []string     `json:"extra"`
}

type ScannerFeeds struct {
	VulnerabilityRules   []DeepfenceRule `json:"vulnerability_rules"`
	SecretRules          []DeepfenceRule `json:"secret_rules"`
	MalwareRules         []DeepfenceRule `json:"malware_rules"`
	ComplianceRules      []DeepfenceRule `json:"compliance_rules"`
	CloudComplianceRules []DeepfenceRule `json:"cloud_compliance_rules"`
}

type TracerFeeds struct {
	NetworkRules      []DeepfenceRule `json:"network_rules"`
	FilesystemRules   []DeepfenceRule `json:"filesystem_rules"`
	ProcessRules      []DeepfenceRule `json:"process_rules"`
	ExternalArtefacts []Artefact      `json:"external_artefacts"`
}

type Artefact struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content []byte `json:"content"`
}

type DeepfenceRule struct {
	RuleID      string `json:"rule_id"`
	Type        string `json:"type"`
	Payload     string `json:"payload"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}
