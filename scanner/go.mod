module github.com/sentinel-api/scanner

go 1.22

require (
	github.com/fatih/color v1.16.0
	github.com/google/uuid v1.6.0
	github.com/spf13/cobra v1.8.0
	go.uber.org/zap v1.27.0
	golang.org/x/net v0.24.0
	golang.org/x/time v0.5.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
)

// NVD API 2.0 integration uses only Go standard library (encoding/json, net/http, regexp).
// No additional third-party dependencies are required.
