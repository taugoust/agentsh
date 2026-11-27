package audit

import (
	"time"
)

// Event represents a single audited filesystem action.
type Event struct {
	Op         string `json:"op"`
	Path       string `json:"path,omitempty"`
	DstPath    string `json:"dst_path,omitempty"`
	Result     string `json:"result,omitempty"` // allowed|blocked|diverted|error
	Reason     string `json:"reason,omitempty"`
	TrashToken string `json:"trash_token,omitempty"`
	Size       int64  `json:"size,omitempty"`
	LinkCount  int    `json:"nlink,omitempty"`

	PID     int       `json:"pid"`
	UID     int       `json:"uid"`
	GID     int       `json:"gid"`
	Session string    `json:"session,omitempty"`
	TS      time.Time `json:"ts"`
}
