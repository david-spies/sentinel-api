// StaticFallbackPublic is the exported shim that engine/client.go calls
// when ScanModes.CVELookup is disabled. It exposes the internal staticFallback
// function without requiring the full NVD client to be initialised.
package nvd

import "github.com/sentinel-api/scanner/internal/models"

// StaticFallbackPublic returns CVEDetail records from the static lookup table
// for cases where NVD live lookup is disabled (NVDOffline=true or CVELookup=false).
func StaticFallbackPublic(serverHeader string) []models.CVEDetail {
	return staticFallback(serverHeader)
}
