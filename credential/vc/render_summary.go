package vc

// SummaryTemplate is the summary object of WD-20261013 §2.2.1.2. It is both the
// template a summary render method carries and, with its JSON Pointers
// resolved, the output RenderSummary returns.
type SummaryTemplate struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Icon        string         `json:"icon,omitempty"`
	Theme       *SummaryTheme  `json:"theme,omitempty"`
	Fields      []SummaryField `json:"fields"`
	ValidFrom   string         `json:"validFrom,omitempty"`
	ValidUntil  string         `json:"validUntil,omitempty"`
}

type SummaryTheme struct {
	PrimaryColor string `json:"primaryColor,omitempty"`
	AccentColor  string `json:"accentColor,omitempty"`
}

type SummaryField struct {
	Label     string `json:"label"`
	Value     string `json:"value"`
	Language  string `json:"language,omitempty"`
	Direction string `json:"direction,omitempty"`
}
