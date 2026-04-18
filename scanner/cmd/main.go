// Package main is the CLI entry point for the Sentinel-API scanner.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"

	"github.com/sentinel-api/scanner/internal/engine"
	"github.com/sentinel-api/scanner/internal/models"
)

var Version = "2.4.1"

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

var (
	flagTarget      string
	flagConcurrency int
	flagTimeout     time.Duration
	flagRateLimit   int
	flagWordlist    string
	flagOpenAPI     string
	flagToken       string
	flagAPIKey      string
	flagOutputDir   string
	flagAIBackend   string
	flagUserAgent   string
	flagConfigFile  string
	flagVerbose     bool
	flagNoColor     bool
	flagNoRedirects bool

	// Scan mode toggles
	flagNoOWASP    bool
	flagNoRateTest bool
	flagNoPII      bool
	flagNoShadow   bool
	flagFuzz       bool

	// NVD API flags (new)
	flagNVDLookup   bool          // --nvd-lookup: enable live NVD CVE lookup
	flagNVDAPIKey   string        // --nvd-api-key: NVD API key (50 req/30s vs 5/30s)
	flagNVDTimeout  time.Duration // --nvd-timeout: per-request NVD timeout
	flagNVDOffline  bool          // --nvd-offline: force static fallback
	flagNVDCacheTTL time.Duration // --nvd-cache-ttl: in-memory cache TTL
)

// ---------------------------------------------------------------------------
// Root command
// ---------------------------------------------------------------------------

var rootCmd = &cobra.Command{
	Use:   "sentinel-api",
	Short: "Sentinel-API — enterprise-grade API security scanner",
	Long: fmt.Sprintf(`
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██████╗ ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██╔══██╗██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██████╔╝██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██╔═══╝ ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║     ██║
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝

  v%s · OWASP API Security Top 10 (2023) · NVD API 2.0 · CISA KEV · AI Remediation`, Version),
	SilenceUsage: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run:   func(cmd *cobra.Command, args []string) { fmt.Printf("sentinel-api v%s\n", Version) },
}

// ---------------------------------------------------------------------------
// Scan command
// ---------------------------------------------------------------------------

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a full security scan against a target API",
	Example: `  # Full scan with live NVD CVE lookup
  sentinel-api scan --target https://api.example.com --nvd-lookup

  # Authenticated scan with NVD API key (50 req/30s rate limit)
  sentinel-api scan \
    --target https://api.example.com \
    --token "eyJ..." \
    --nvd-lookup \
    --nvd-api-key "YOUR-NVD-KEY"

  # Air-gapped scan (static CVE table, no internet for CVE lookup)
  sentinel-api scan --target https://api.example.com --nvd-offline

  # CI/CD gate — exits 1 on any critical finding
  sentinel-api scan \
    --target https://staging.api.example.com \
    --nvd-lookup \
    --no-color`,
	RunE: runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	log, err := buildLogger(flagVerbose)
	if err != nil {
		return err
	}
	defer log.Sync() //nolint:errcheck

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	if !flagNoColor {
		printBanner()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		color.Yellow("\n  Scan interrupted — saving partial results...")
		cancel()
	}()

	onEvent := buildEventHandler(flagNoColor)

	orch := engine.NewOrchestrator(cfg, log.Sugar(), onEvent)
	result, err := orch.Run(ctx)
	if result != nil {
		printSummary(result, flagNoColor)
		if result.Summary.CriticalCount > 0 {
			os.Exit(1)
		}
	}
	return err
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

func loadConfig() (*models.ScanConfig, error) {
	cfg := defaultConfig()

	cfgFile := flagConfigFile
	if cfgFile == "" {
		if _, err := os.Stat("sentinel-api.yaml"); err == nil {
			cfgFile = "sentinel-api.yaml"
		}
	}
	if cfgFile != "" {
		data, err := os.ReadFile(cfgFile)
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", cfgFile, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", cfgFile, err)
		}
	}

	// CLI flags always win
	if flagTarget != "" {
		cfg.Target = flagTarget
	}
	if cfg.Target == "" {
		return nil, fmt.Errorf("--target is required (or set 'target' in sentinel-api.yaml)")
	}
	if flagConcurrency > 0 {
		cfg.Concurrency = flagConcurrency
	}
	if flagTimeout > 0 {
		cfg.Timeout = flagTimeout
	}
	if flagRateLimit > 0 {
		cfg.RateLimit = flagRateLimit
	}
	if flagWordlist != "" {
		cfg.WordlistPath = flagWordlist
	}
	if flagOpenAPI != "" {
		cfg.OpenAPISpecURL = flagOpenAPI
	}
	if flagToken != "" {
		cfg.BearerToken = flagToken
	}
	if flagAPIKey != "" {
		cfg.APIKey = flagAPIKey
	}
	if flagOutputDir != "" {
		cfg.OutputPath = flagOutputDir
	}
	if flagAIBackend != "" {
		cfg.AIBackendURL = flagAIBackend
	}
	if flagUserAgent != "" {
		cfg.UserAgent = flagUserAgent
	}
	cfg.FollowRedirects = !flagNoRedirects

	// Scan mode overrides
	if flagNoOWASP {
		cfg.ScanModes.OWASP = false
	}
	if flagNoRateTest {
		cfg.ScanModes.RateLimitTest = false
	}
	if flagNoPII {
		cfg.ScanModes.PIIDetection = false
	}
	if flagNoShadow {
		cfg.ScanModes.ShadowAPI = false
	}
	if flagFuzz {
		cfg.ScanModes.Fuzzing = true
	}

	// NVD flags
	if flagNVDLookup {
		cfg.ScanModes.CVELookup = true
	}
	if flagNVDOffline {
		cfg.NVDOffline = true
		cfg.ScanModes.CVELookup = false // offline implies no live lookup
	}
	if flagNVDAPIKey != "" {
		cfg.NVDAPIKey = flagNVDAPIKey
	}
	if flagNVDTimeout > 0 {
		cfg.NVDTimeout = flagNVDTimeout
	}
	if flagNVDCacheTTL > 0 {
		cfg.NVDCacheTTL = flagNVDCacheTTL
	}

	return cfg, nil
}

func defaultConfig() *models.ScanConfig {
	return &models.ScanConfig{
		Concurrency:     25,
		Timeout:         10 * time.Second,
		RateLimit:       50,
		OutputPath:      "./reports",
		FollowRedirects: true,
		NVDTimeout:      15 * time.Second,
		NVDCacheTTL:     24 * time.Hour,
		ScanModes: models.ScanModes{
			Discovery:     true,
			OWASP:         true,
			RateLimitTest: true,
			PIIDetection:  true,
			ShadowAPI:     true,
			Fuzzing:       false,
			CVELookup:     false, // opt-in; requires network to NVD
		},
	}
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

func printBanner() {
	color.New(color.FgHiBlue, color.Bold).Printf("\n  Sentinel-API v%s  —  Enterprise API Security Scanner\n", Version)
	color.New(color.FgHiBlack).Println("  ──────────────────────────────────────────────────────\n")
}

func buildEventHandler(noColor bool) func(engine.ScanEvent) {
	return func(e engine.ScanEvent) {
		if e.Error != nil {
			color.Red("  [ERROR] %s: %v", e.Phase, e.Error)
			return
		}
		if noColor {
			fmt.Printf("  [%s] %s\n", e.Phase, e.Message)
			return
		}
		icon := map[string]string{
			"fingerprint": "◎", "discovery": "◈",
			"analysis": "◆", "reporting": "◇", "complete": "✓",
		}[e.Phase]
		if icon == "" {
			icon = "·"
		}
		color.Cyan("  %s [%s] %s\n", icon, e.Phase, e.Message)
	}
}

func printSummary(result *models.ScanResult, noColor bool) {
	fmt.Println()
	if noColor {
		fmt.Println("  === SCAN COMPLETE ===")
	} else {
		color.New(color.FgHiGreen, color.Bold).Println("  ✓ Scan complete")
	}
	fmt.Printf("\n  Target    : %s\n", result.Target)
	fmt.Printf("  Scan ID   : %s\n", result.ScanID)
	fmt.Printf("  Duration  : %s\n", result.Duration)
	fmt.Printf("  Endpoints : %d  (%d shadow/zombie)\n\n",
		result.Summary.TotalEndpoints,
		result.Summary.UndocumentedCount+result.Summary.ZombieCount,
	)

	printCount(noColor, "  Critical", result.Summary.CriticalCount, color.FgHiRed)
	printCount(noColor, "  High    ", result.Summary.HighCount, color.FgYellow)
	printCount(noColor, "  Medium  ", result.Summary.MediumCount, color.FgHiMagenta)
	printCount(noColor, "  Low     ", result.Summary.LowCount, color.FgHiGreen)

	if result.Summary.CVETotal > 0 {
		fmt.Println()
		fmt.Printf("  CVEs (NVD): %d total", result.Summary.CVETotal)
		if result.Summary.CVECritical > 0 {
			fmt.Printf(" · %d critical", result.Summary.CVECritical)
		}
		if result.Summary.CVEExploited > 0 {
			if noColor {
				fmt.Printf(" · %d CISA KEV", result.Summary.CVEExploited)
			} else {
				fmt.Printf(" · ")
				color.New(color.FgHiRed, color.Bold).Printf("%d CISA KEV", result.Summary.CVEExploited)
			}
		}
		fmt.Println()
	}

	fmt.Println()
	scoreAttr := scoreColour(result.SentinelScore)
	if noColor {
		fmt.Printf("  SentinelRank : %d / 100\n", result.SentinelScore)
	} else {
		color.New(scoreAttr, color.Bold).Printf("  SentinelRank : %d / 100\n", result.SentinelScore)
	}
	fmt.Printf("\n  Reports → %s/sentinel_%s.*\n\n", result.Summary, result.ScanID)
}

func printCount(noColor bool, label string, count int, attr color.Attribute) {
	if noColor || count == 0 {
		fmt.Printf("%s : %d\n", label, count)
		return
	}
	color.New(attr).Printf("%s : %d\n", label, count)
}

func scoreColour(score int) color.Attribute {
	switch {
	case score >= 80:
		return color.FgHiGreen
	case score >= 60:
		return color.FgYellow
	default:
		return color.FgHiRed
	}
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

func buildLogger(verbose bool) (*zap.Logger, error) {
	level := zapcore.WarnLevel
	if verbose {
		level = zapcore.DebugLevel
	}
	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Encoding:         "console",
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "T",
			LevelKey:       "L",
			MessageKey:     "M",
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeTime:     zapcore.TimeEncoderOfLayout("15:04:05"),
			EncodeDuration: zapcore.StringDurationEncoder,
		},
	}
	return cfg.Build()
}

// ---------------------------------------------------------------------------
// Command registration & main
// ---------------------------------------------------------------------------

func init() {
	scanCmd.Flags().StringVarP(&flagTarget, "target", "t", "", "Target API base URL (required)")
	scanCmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", 0, "Worker goroutines (default 25)")
	scanCmd.Flags().DurationVar(&flagTimeout, "timeout", 0, "Per-request timeout (default 10s)")
	scanCmd.Flags().IntVar(&flagRateLimit, "rate-limit", 0, "Max requests/second (default 50)")
	scanCmd.Flags().StringVarP(&flagWordlist, "wordlist", "w", "", "Custom wordlist path")
	scanCmd.Flags().StringVar(&flagOpenAPI, "openapi", "", "OpenAPI spec URL for schema-diff shadow detection")
	scanCmd.Flags().StringVar(&flagToken, "token", "", "Bearer token for authenticated scanning")
	scanCmd.Flags().StringVar(&flagAPIKey, "api-key", "", "API key (X-API-Key header)")
	scanCmd.Flags().StringVarP(&flagOutputDir, "output", "o", "", "Report output directory (default ./reports)")
	scanCmd.Flags().StringVar(&flagAIBackend, "ai-backend", "", "AI service URL (HTTP or grpc://)")
	scanCmd.Flags().StringVar(&flagUserAgent, "user-agent", "", "Custom User-Agent")
	scanCmd.Flags().StringVar(&flagConfigFile, "config", "", "Path to sentinel-api.yaml")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Debug logging")
	scanCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Plain text output for CI")
	scanCmd.Flags().BoolVar(&flagNoRedirects, "no-follow-redirects", false, "Do not follow HTTP redirects")

	// Scan modes
	scanCmd.Flags().BoolVar(&flagNoOWASP, "no-owasp", false, "Skip OWASP Top 10 checks")
	scanCmd.Flags().BoolVar(&flagNoRateTest, "no-rate-test", false, "Skip rate-limit burst testing")
	scanCmd.Flags().BoolVar(&flagNoPII, "no-pii", false, "Skip PII detection")
	scanCmd.Flags().BoolVar(&flagNoShadow, "no-shadow", false, "Skip shadow API detection")
	scanCmd.Flags().BoolVar(&flagFuzz, "fuzz", false, "Enable parameter fuzzing")

	// NVD flags
	scanCmd.Flags().BoolVar(&flagNVDLookup, "nvd-lookup", false,
		"Enable live NVD API 2.0 CVE lookup (requires internet access to services.nvd.nist.gov)")
	scanCmd.Flags().StringVar(&flagNVDAPIKey, "nvd-api-key", "",
		"NVD API key — raises rate limit from 5 to 50 req/30s (register free at https://nvd.nist.gov/developers/request-an-api-key)")
	scanCmd.Flags().DurationVar(&flagNVDTimeout, "nvd-timeout", 0,
		"NVD per-request timeout (default 15s)")
	scanCmd.Flags().BoolVar(&flagNVDOffline, "nvd-offline", false,
		"Force static CVE fallback table (air-gapped environments)")
	scanCmd.Flags().DurationVar(&flagNVDCacheTTL, "nvd-cache-ttl", 0,
		"NVD in-memory cache TTL (default 24h)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
