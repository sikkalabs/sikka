package sikka

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

type ReleaseMetadata struct {
	SoftwareVersion string   `json:"software_version"`
	ProtocolVersion string   `json:"protocol_version"`
	Capabilities    []string `json:"capabilities"`
}

var (
	//go:embed release.json
	releaseJSON []byte

	releaseOnce sync.Once
	releaseMeta ReleaseMetadata
	releaseErr  error
)

func CurrentRelease() ReleaseMetadata {
	releaseOnce.Do(func() {
		releaseErr = json.Unmarshal(releaseJSON, &releaseMeta)
		if releaseErr != nil {
			releaseErr = fmt.Errorf("parse embedded release metadata: %w", releaseErr)
			return
		}
		if releaseMeta.SoftwareVersion == "" {
			releaseErr = fmt.Errorf("embedded release metadata is missing software_version")
			return
		}
		if releaseMeta.ProtocolVersion == "" {
			releaseErr = fmt.Errorf("embedded release metadata is missing protocol_version")
		}
	})
	if releaseErr != nil {
		panic(releaseErr)
	}
	meta := releaseMeta
	meta.Capabilities = make([]string, len(releaseMeta.Capabilities))
	copy(meta.Capabilities, releaseMeta.Capabilities)
	return meta
}