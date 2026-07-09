package generators

import (
	"encoding/json"
	"os"
)

type activitiesConfig struct {
	Activities map[string]activityConfigEntry `json:"activities"`
}

type activityConfigEntry struct {
	IntentType string `json:"intentType"`
	ResultType string `json:"resultType"`
	Internal   bool   `json:"internal"`
}

func readActivitiesConfig(path string) (*activitiesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg activitiesConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
