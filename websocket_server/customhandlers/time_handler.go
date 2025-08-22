package customhandlers

import (
	"context"
	"encoding/json"
	"time"

	"websocketserver/ws"
)

type TimeHandler struct{}

func (h *TimeHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
	var input struct {
		Format string `json:"format,omitempty"`
		Zone   string `json:"zone,omitempty"`
	}

	if len(params) > 0 {
		json.Unmarshal(params, &input)
	}

	// Default format if not specified
	if input.Format == "" {
		input.Format = time.RFC3339
	}

	// Get current time
	now := time.Now()
	if input.Zone != "" {
		if loc, err := time.LoadLocation(input.Zone); err == nil {
			now = now.In(loc)
		}
	}

	response := map[string]interface{}{
		"current_time": now.Format(input.Format),
		"unix":         now.Unix(),
		"timezone":     now.Location().String(),
		"requester":    sender,
	}

	return response, nil
}

func init() {
	Register(
		"get_time",
		func() ws.ServerMessageHandler { return &TimeHandler{} },
		"Get current server time with optional format and timezone",
	)
}
