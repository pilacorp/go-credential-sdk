package vc

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
