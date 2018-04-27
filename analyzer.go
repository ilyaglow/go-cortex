package cortex

const (
	analyzersURL    = "/api/analyzer"
	analyzersByType = analyzersURL + "/type/"
)

// Analyzer defines a specific Cortex Analyzer
type Analyzer struct {
	Author       string      `json:"author"`
	BaseConfig   string      `json:"baseConfig"`
	CreatedAt    int64       `json:"createdAt"`
	CreatedBy    string      `json:"createdBy"`
	DataTypeList []string    `json:"dataTypeList"`
	DefinitionID string      `json:"analyzerDefinitionId"`
	Description  string      `json:"description"`
	ID           string      `json:"id"`
	JobCache     interface{} `json:"jobCache,omitempty"` // unknown
	License      string      `json:"license"`
	Name         string      `json:"name"`
	Rate         int         `json:"rate,omitempty"`
	RateUnit     string      `json:"rateUnit,omitempty"`
	URL          string      `json:"url"`
	UpdatedAt    int64       `json:"updatedAt,omitempty"`
	UpdatedBy    string      `json:"updatedBy,omitempty"`
	Version      string      `json:"version"`
}
