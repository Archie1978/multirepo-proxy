package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"multirepo-proxy/auth"
	"multirepo-proxy/auth/basic"
	"multirepo-proxy/config"
	"multirepo-proxy/core"
	coredb "multirepo-proxy/core/db"
	aptdriver "multirepo-proxy/drivers/apt"
	"multirepo-proxy/drivers/cran"
	"multirepo-proxy/drivers/docker"
	"multirepo-proxy/drivers/goproxy"
	"multirepo-proxy/drivers/npm"
	"multirepo-proxy/drivers/pypi"
	"multirepo-proxy/logs"
	"multirepo-proxy/security"
	"multirepo-proxy/security/epss"
	"multirepo-proxy/security/nvd"
	"multirepo-proxy/security/osv"
	"multirepo-proxy/security/sonatype"
	"multirepo-proxy/serviceweb/api"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "multirepo-proxy",
	Short: "Multi-repo proxy with quarantine",
	Long: `multirepo-proxy exposes a single entry point for apt, Docker, PyPI, Go and CRAN.
Each incoming artifact is quarantined for manual validation before distribution.

Configuration: YAML file (--config) and/or MULTIREPO_* environment variables.
Example: MULTIREPO_SERVER_ADDR=":9000" MULTIREPO_DRIVERS_DOCKER_PASSWORD="token"`,
	SilenceUsage: true,
	RunE:         serve,
}

// Execute is the entry point called from main().
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"YAML configuration file (default: /etc/multirepo/config.yaml or ./config.yaml)")

	// Quick override flags — useful for tests and CLI overrides.
	rootCmd.Flags().String("addr", "", "proxy listen address (e.g.: :8222)")
	viper.BindPFlag("server.addr", rootCmd.Flags().Lookup("addr")) //nolint:errcheck
}

// initConfig loads the YAML file then applies environment variables.
// Priority order (highest to lowest):
//  1. CLI flag (--addr, etc.)
//  2. Environment variable  MULTIREPO_<SECTION>_<KEY>
//  3. config.yaml file
//  4. Default values (config.Defaults)
func initConfig() {
	// Apply default values first.
	defaults := config.Defaults()
	setViperDefaults(defaults)

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/multirepo") // canonical path in container
		viper.AddConfigPath(".")              // local development
	}

	// Environment variables: MULTIREPO_DRIVERS_DOCKER_PASSWORD → drivers.docker.password
	viper.SetEnvPrefix("MULTIREPO")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, notFound := err.(viper.ConfigFileNotFoundError); !notFound {
			fmt.Fprintf(os.Stderr, "config read error: %v\n", err)
			os.Exit(1)
		}
		// No file found → continue with defaults + env vars.
	} else {
		fmt.Fprintf(os.Stderr, "configuration loaded from %s\n", viper.ConfigFileUsed())
	}
}

// serve builds and starts the proxy from the resolved configuration.
func serve(_ *cobra.Command, _ []string) error {
	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("cannot read configuration: %w", err)
	}

	// ── Logger ────────────────────────────────────────────────────────────
	logger, err := logs.NewFromConfig(cfg.Logging)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer logger.Close()

	// ── Outbound HTTP proxy ────────────────────────────────────────────────
	applyProxyTransport(cfg.Proxy)
	if cfg.Proxy.HTTP != "" || cfg.Proxy.HTTPS != "" {
		authInfo := ""
		if cfg.Proxy.Username != "" {
			authInfo = cfg.Proxy.Username + ":***"
		}
		logger.Info("outbound proxy enabled",
			logs.String("http", cfg.Proxy.HTTP),
			logs.String("https", cfg.Proxy.HTTPS),
			logs.String("auth", authInfo),
			logs.String("no_proxy", cfg.Proxy.NoProxy),
		)
	}

	// ── Single database ────────────────────────────────────────────────────

	gdb, err := coredb.Open(cfg.Storage.DBPath)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	sqlDB, _ := gdb.DB()
	defer sqlDB.Close()

	// Separate auth database if auth.db_path is set and differs from storage.db_path.
	// Otherwise auth data (users/groups/rules) shares storage.db_path.
	authDB := gdb
	if cfg.Auth.DBPath != "" && cfg.Auth.DBPath != cfg.Storage.DBPath {
		authDB, err = coredb.OpenAuth(cfg.Auth.DBPath)
		if err != nil {
			return fmt.Errorf("auth db: %w", err)
		}
		authSQLDB, _ := authDB.DB()
		defer authSQLDB.Close()
		logger.Info("separate auth database", logs.String("path", cfg.Auth.DBPath))
	}

	// ── Infrastructure ────────────────────────────────────────────────────

	cache, err := core.NewDiskStore(cfg.Storage.CacheDir)
	if err != nil {
		return fmt.Errorf("cache: %w", err)
	}

	quarantine := core.NewQuarantineStore(gdb)
	ruleStore := core.NewRuleStore(authDB)
	groupStore := core.NewGroupStore(authDB)

	// ── Security scanners ─────────────────────────────────────────────────
	quarantine.OnEnqueue = buildScanHook(cfg.Security, quarantine, ruleStore, logger)
	go resumePendingScans(quarantine, logger)

	registry := core.NewRegistry(cache, quarantine)

	// ── Drivers ───────────────────────────────────────────────────────────

	var aptDrv *aptdriver.AptDriver
	if cfg.Drivers.Apt.Enabled {
		d := cfg.Drivers.Apt
		aptCfg := aptdriver.Config{
			Prefix:   d.Prefix,
			Upstream: d.Upstream,
		}
		if d.GPG.KeyringDir != "" {
			aptCfg.GPG = &aptdriver.GPGConfig{
				KeyringDir:     d.GPG.KeyringDir,
				RejectUnsigned: d.GPG.RejectUnsigned,
			}
		}
		aptDrv, err = aptdriver.NewAptDriver(aptCfg)
		if err != nil {
			return fmt.Errorf("apt driver: %w", err)
		}
		registry.Register(aptDrv)
	}

	var cranDrv *cran.CRANDriver
	if cfg.Drivers.CRAN.Enabled {
		d := cfg.Drivers.CRAN
		cranDrv = cran.NewCRANDriver(d.Prefix, d.Upstream)
		registry.Register(cranDrv)
	}

	if cfg.Drivers.Go.Enabled {
		d := cfg.Drivers.Go
		registry.Register(goproxy.NewGoDriver(d.Prefix, d.Upstream))
	}

	if cfg.Drivers.Npm.Enabled {
		d := cfg.Drivers.Npm
		registry.Register(npm.NewNpmDriver(d.Prefix, d.Upstream))
	}

	if cfg.Drivers.PyPI.Enabled {
		d := cfg.Drivers.PyPI
		registry.Register(pypi.NewPyPIDriver(d.Prefix, d.Upstream, cache, quarantine))
	}

	if cfg.Drivers.Docker.Enabled {
		d := cfg.Drivers.Docker
		registry.Register(docker.NewDockerDriver(docker.Config{
			Prefix:   d.Prefix,
			Upstream: d.Upstream,
			Username: d.Username,
			Password: d.Password,
			Cosign: docker.CosignConfig{
				Enabled:          d.Cosign.Enabled,
				PublicKeyFiles:   d.Cosign.PublicKeyFiles,
				RequireSignature: d.Cosign.RequireSignature,
			},
		}, cache, quarantine))
	}

	// ── Authentication ────────────────────────────────────────────────────

	authenticator, err := auth.NewFromConfig(cfg.Auth, authDB)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if cfg.Auth.Provider != "" && cfg.Auth.Provider != "none" {
		logger.Info("authentication enabled", logs.String("provider", cfg.Auth.Provider))
	}

	// ── HTTP routes ───────────────────────────────────────────────────────

	// DBStore exposed to AdminAPI for user management (always active).
	userStore := basic.NewDBStore(authDB)

	adminAPI := api.NewAdminAPI(quarantine, ruleStore, groupStore, userStore, aptDrv, cranDrv, logger)
	adminUI := &api.AdminUIHandler{API: adminAPI}

	// Proxy access control: active only when authentication is enabled.
	// auth_required: false bypasses both auth and the access check, regardless of enabled status
	// (unauthenticated request → no groups → would be blocked otherwise).
	if cfg.Auth.Provider != "" && cfg.Auth.Provider != "none" {
		noAuthDrivers := map[string]bool{}
		if !cfg.Drivers.Apt.AuthRequired    { noAuthDrivers["apt"]    = true }
		if !cfg.Drivers.Docker.AuthRequired { noAuthDrivers["docker"] = true }
		if !cfg.Drivers.PyPI.AuthRequired   { noAuthDrivers["pip"]    = true }
		if !cfg.Drivers.Go.AuthRequired     { noAuthDrivers["go"]     = true }
		if !cfg.Drivers.CRAN.AuthRequired   { noAuthDrivers["r"]      = true }
		if !cfg.Drivers.Npm.AuthRequired    { noAuthDrivers["npm"]    = true }

		registry.SetAccessChecker(func(groups []string, repoType string) bool {
			if noAuthDrivers[repoType] {
				return true // auth_required: false → open access
			}
			return groupStore.ResolvePerms(groups, false).AllowsRepo(repoType)
		})
	}

	mux := http.NewServeMux()
	mux.Handle("/admin", http.RedirectHandler("/admin/", http.StatusMovedPermanently))
	mux.HandleFunc("/favicon.ico", api.ServeFavicon)
	authenticator.RegisterRoutes(mux) // OIDC endpoints (/admin/auth/*) before the catch-all
	mux.Handle("/admin/", authenticator.Middleware(adminUI))

	// Proxy routing with conditional auth per driver.
	// All configured prefixes are registered regardless of enabled status:
	// a disabled driver with auth_required: false returns 404 (not registered),
	// not 401 (misleading auth error).
	authEnabled := cfg.Auth.Provider != "" && cfg.Auth.Provider != "none"
	if authEnabled {
		driverAuth := map[string]bool{}
		driverAuth[cfg.Drivers.Apt.Prefix]    = cfg.Drivers.Apt.AuthRequired
		driverAuth[cfg.Drivers.Docker.Prefix] = cfg.Drivers.Docker.AuthRequired
		driverAuth[cfg.Drivers.PyPI.Prefix]   = cfg.Drivers.PyPI.AuthRequired
		driverAuth[cfg.Drivers.Go.Prefix]     = cfg.Drivers.Go.AuthRequired
		driverAuth[cfg.Drivers.CRAN.Prefix]   = cfg.Drivers.CRAN.AuthRequired
		driverAuth[cfg.Drivers.Npm.Prefix]    = cfg.Drivers.Npm.AuthRequired

		authedRegistry := authenticator.Middleware(registry)
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/admin/", http.StatusFound)
				return
			}
			for prefix, required := range driverAuth {
				if strings.HasPrefix(r.URL.Path, prefix) {
					if required {
						authedRegistry.ServeHTTP(w, r)
					} else {
						registry.ServeHTTP(w, r)
					}
					return
				}
			}
			// Unrecognized prefix → default auth.
			authedRegistry.ServeHTTP(w, r)
		}))
	} else {
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/admin/", http.StatusFound)
				return
			}
			registry.ServeHTTP(w, r)
		}))
	}

	handler := logs.HTTPMiddleware(logger)(mux)

	tls := cfg.Server.TLS
	scheme := "http"
	if tls.Enabled {
		scheme = "https"
	}

	logger.Info("multirepo-proxy started",
		logs.String("addr", cfg.Server.Addr),
		logs.Bool("tls", tls.Enabled),
	)
	logger.Info("admin UI", logs.String("url", scheme+"://"+cfg.Server.Addr+"/admin/"))
	for _, d := range registry.Drivers() {
		logger.Info("driver active",
			logs.String("name", d.Name()),
			logs.String("url", scheme+"://"+cfg.Server.Addr+d.Prefix()),
		)
	}

	if !tls.Enabled {
		return http.ListenAndServe(cfg.Server.Addr, handler)
	}

	if tls.CertFile == "" || tls.KeyFile == "" {
		return fmt.Errorf("tls enabled but cert_file or key_file is missing")
	}

	return http.ListenAndServeTLS(cfg.Server.Addr, tls.CertFile, tls.KeyFile, handler)
}

// setViperDefaults flattens the Config struct into dotted viper keys.
func setViperDefaults(d config.Config) {
	viper.SetDefault("server.addr", d.Server.Addr)
	viper.SetDefault("server.tls.enabled", d.Server.TLS.Enabled)
	viper.SetDefault("server.tls.cert_file", d.Server.TLS.CertFile)
	viper.SetDefault("server.tls.key_file", d.Server.TLS.KeyFile)

	viper.SetDefault("logging.level", d.Logging.Level)
	viper.SetDefault("logging.stdout.enabled", d.Logging.Stdout.Enabled)
	viper.SetDefault("logging.stdout.format", d.Logging.Stdout.Format)
	viper.SetDefault("logging.file.enabled", d.Logging.File.Enabled)
	viper.SetDefault("logging.file.path", d.Logging.File.Path)
	viper.SetDefault("logging.file.max_size_mb", d.Logging.File.MaxSizeMB)
	viper.SetDefault("logging.file.max_backups", d.Logging.File.MaxBackups)
	viper.SetDefault("logging.file.compress", d.Logging.File.Compress)
	viper.SetDefault("logging.logstash.enabled", d.Logging.Logstash.Enabled)
	viper.SetDefault("logging.logstash.host", d.Logging.Logstash.Host)
	viper.SetDefault("logging.logstash.protocol", d.Logging.Logstash.Protocol)
	viper.SetDefault("logging.loki.enabled", d.Logging.Loki.Enabled)
	viper.SetDefault("logging.loki.url", d.Logging.Loki.URL)
	viper.SetDefault("logging.loki.labels", d.Logging.Loki.Labels)
	viper.SetDefault("logging.loki.batch_size", d.Logging.Loki.BatchSize)
	viper.SetDefault("logging.loki.batch_wait", d.Logging.Loki.BatchWait)
	viper.SetDefault("logging.loki.timeout", d.Logging.Loki.Timeout)

	viper.SetDefault("storage.cache_dir", d.Storage.CacheDir)
	viper.SetDefault("storage.db_path", d.Storage.DBPath)

	viper.SetDefault("proxy.http", d.Proxy.HTTP)
	viper.SetDefault("proxy.https", d.Proxy.HTTPS)
	viper.SetDefault("proxy.username", d.Proxy.Username)
	viper.SetDefault("proxy.password", d.Proxy.Password)
	viper.SetDefault("proxy.no_proxy", d.Proxy.NoProxy)

	viper.SetDefault("auth.provider", d.Auth.Provider)
	viper.SetDefault("auth.db_path", d.Auth.DBPath)
	viper.SetDefault("auth.local_users", d.Auth.LocalUsers)
	viper.SetDefault("auth.session_secret", d.Auth.SessionSecret)
	viper.SetDefault("auth.basic.realm", d.Auth.Basic.Realm)
	viper.SetDefault("auth.basic.htpasswd_file", d.Auth.Basic.HtpasswdFile)
	viper.SetDefault("auth.ldap.group_base_dn", d.Auth.LDAP.GroupBaseDN)
	viper.SetDefault("auth.ldap.group_filter", d.Auth.LDAP.GroupFilter)
	viper.SetDefault("auth.ldap.group_attribute", d.Auth.LDAP.GroupAttribute)

	viper.SetDefault("auth.oidc.issuer", d.Auth.OIDC.Issuer)
	viper.SetDefault("auth.oidc.client_id", d.Auth.OIDC.ClientID)
	viper.SetDefault("auth.oidc.client_secret", d.Auth.OIDC.ClientSecret)
	viper.SetDefault("auth.oidc.redirect_url", d.Auth.OIDC.RedirectURL)
	viper.SetDefault("auth.oidc.scopes", d.Auth.OIDC.Scopes)
	viper.SetDefault("auth.oidc.session_ttl", d.Auth.OIDC.SessionTTL)

	viper.SetDefault("drivers.apt.enabled", d.Drivers.Apt.Enabled)
	viper.SetDefault("drivers.apt.prefix", d.Drivers.Apt.Prefix)
	viper.SetDefault("drivers.apt.upstream", d.Drivers.Apt.Upstream)
	viper.SetDefault("drivers.apt.gpg.keyring_dir", d.Drivers.Apt.GPG.KeyringDir)
	viper.SetDefault("drivers.apt.gpg.reject_unsigned", d.Drivers.Apt.GPG.RejectUnsigned)

	viper.SetDefault("drivers.docker.enabled", d.Drivers.Docker.Enabled)
	viper.SetDefault("drivers.docker.prefix", d.Drivers.Docker.Prefix)
	viper.SetDefault("drivers.docker.upstream", d.Drivers.Docker.Upstream)
	viper.SetDefault("drivers.docker.username", d.Drivers.Docker.Username)
	viper.SetDefault("drivers.docker.password", d.Drivers.Docker.Password)
	viper.SetDefault("drivers.docker.cosign.enabled", d.Drivers.Docker.Cosign.Enabled)
	viper.SetDefault("drivers.docker.cosign.public_key_files", d.Drivers.Docker.Cosign.PublicKeyFiles)
	viper.SetDefault("drivers.docker.cosign.require_signature", d.Drivers.Docker.Cosign.RequireSignature)

	viper.SetDefault("drivers.pypi.enabled", d.Drivers.PyPI.Enabled)
	viper.SetDefault("drivers.pypi.prefix", d.Drivers.PyPI.Prefix)
	viper.SetDefault("drivers.pypi.upstream", d.Drivers.PyPI.Upstream)

	viper.SetDefault("drivers.go.enabled", d.Drivers.Go.Enabled)
	viper.SetDefault("drivers.go.prefix", d.Drivers.Go.Prefix)
	viper.SetDefault("drivers.go.upstream", d.Drivers.Go.Upstream)

	viper.SetDefault("drivers.cran.enabled", d.Drivers.CRAN.Enabled)
	viper.SetDefault("drivers.cran.prefix", d.Drivers.CRAN.Prefix)
	viper.SetDefault("drivers.cran.upstream", d.Drivers.CRAN.Upstream)

	viper.SetDefault("drivers.npm.enabled", d.Drivers.Npm.Enabled)
	viper.SetDefault("drivers.npm.prefix", d.Drivers.Npm.Prefix)
	viper.SetDefault("drivers.npm.upstream", d.Drivers.Npm.Upstream)

	viper.SetDefault("security.osv.enabled", d.Security.OSV.Enabled)
	viper.SetDefault("security.osv.timeout", d.Security.OSV.Timeout)
	viper.SetDefault("security.nvd.enabled", d.Security.NVD.Enabled)
	viper.SetDefault("security.nvd.api_key", d.Security.NVD.APIKey)
	viper.SetDefault("security.nvd.timeout", d.Security.NVD.Timeout)
	viper.SetDefault("security.sonatype.enabled", d.Security.Sonatype.Enabled)
	viper.SetDefault("security.sonatype.token", d.Security.Sonatype.Token)
	viper.SetDefault("security.sonatype.timeout", d.Security.Sonatype.Timeout)
	viper.SetDefault("security.epss.enabled", d.Security.EPSS.Enabled)
	viper.SetDefault("security.epss.timeout", d.Security.EPSS.Timeout)
}

// buildScanHook builds the OnEnqueue callback that triggers security scans.
// Returns nil if no scanner is enabled.
func buildScanHook(cfg config.SecurityConfig, q *core.QuarantineStore, rules *core.RuleStore, log logs.Logger) func(*core.PackageRequest) {
	// EPSS enrichment (post-scan, non-blocking).
	var epssFetcher *epss.Fetcher
	if cfg.EPSS.Enabled {
		to, err := time.ParseDuration(cfg.EPSS.Timeout)
		if err != nil {
			to = 10 * time.Second
		}
		epssFetcher = epss.New(to)
		log.Info("enrichment enabled", logs.String("source", "EPSS"))
	}

	var scanners []security.Scanner

	if cfg.OSV.Enabled {
		to, err := time.ParseDuration(cfg.OSV.Timeout)
		if err != nil {
			to = 10 * time.Second
		}
		scanners = append(scanners, osv.New(to))
		log.Info("scanner enabled", logs.String("scanner", "OSV"))
	}

	if cfg.NVD.Enabled {
		to, err := time.ParseDuration(cfg.NVD.Timeout)
		if err != nil {
			to = 15 * time.Second
		}
		scanners = append(scanners, nvd.New(cfg.NVD.APIKey, to))
		log.Info("scanner enabled", logs.String("scanner", "NVD"))
	}

	if cfg.Sonatype.Enabled {
		to, err := time.ParseDuration(cfg.Sonatype.Timeout)
		if err != nil {
			to = 15 * time.Second
		}
		scanners = append(scanners, sonatype.New(cfg.Sonatype.Token, to))
		log.Info("scanner enabled", logs.String("scanner", "Sonatype"))
	}

	if len(scanners) == 0 {
		return nil
	}

	multi := security.NewMultiScanner(scanners...)

	return func(req *core.PackageRequest) {
		// Notify waiting HTTP requests as soon as the scan is done,
		// regardless of outcome (success, error, panic).
		defer q.NotifyScanDone(req.ID)

		_ = q.SetScanStatus(req.ID, "scanning", "")

		pkg := security.Package{
			Name:      req.Name,
			Version:   req.Version,
			Ecosystem: security.EcosystemFor(req.RepoType),
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		vulns, err := multi.Scan(ctx, pkg)
		if err != nil {
			_ = q.SetScanStatus(req.ID, "error", err.Error())
			log.Warn("security scan failed",
				logs.String("package", req.Name),
				logs.String("version", req.Version),
				logs.Err(err),
			)
			return
		}

		// EPSS enrichment: adds exploitation probability to each CVE.
		if epssFetcher != nil {
			enriched, epssErr := epssFetcher.Enrich(ctx, vulns)
			if epssErr != nil {
				log.Warn("EPSS enrichment failed",
					logs.String("package", req.Name),
					logs.String("version", req.Version),
					logs.Err(epssErr),
				)
			} else {
				var n int
				for _, v := range enriched {
					if v.EPSS > 0 {
						n++
					}
				}
				log.Debug("EPSS enrichment done",
					logs.String("package", req.Name),
					logs.Int("cves_enriched", n),
				)
			}
			vulns = enriched
		}

		findings := make([]core.SecurityFinding, 0, len(vulns))
		for _, v := range vulns {
			findings = append(findings, core.SecurityFinding{
				ID:             v.ID,
				Source:         v.Source,
				Severity:       string(v.Severity),
				CVSS:           v.CVSS,
				CWE:            v.CWE,
				EPSS:           v.EPSS,
				EPSSPercentile: v.EPSSPercentile,
				Title:          v.Title,
				Description:    v.Description,
				References:     v.References,
			})
		}

		_ = q.SaveFindings(req.ID, findings)
		_ = q.SetScanStatus(req.ID, "done", "")

		if len(findings) > 0 {
			log.Warn("vulnerabilities detected",
				logs.String("package", req.Name),
				logs.String("version", req.Version),
				logs.Int("count", len(findings)),
			)
		} else {
			log.Debug("clean scan",
				logs.String("package", req.Name),
				logs.String("version", req.Version),
			)
		}

		// Check if human review is mandatory (e.g. Cosign signature failed).
		// In that case block any auto-approval regardless of scan outcome.
		if req.RequireHumanReview {
			log.Warn("auto-approval blocked: human review required",
				logs.String("package", req.Name),
				logs.String("version", req.Version),
				logs.String("reason", req.SignatureError),
			)
			return
		}

		// Evaluate auto-approval/quarantine rules.
		result, evalErr := rules.Evaluate(req.RepoType, findings)
		if evalErr != nil {
			log.Warn("rule evaluation failed", logs.Err(evalErr))
		} else if result.HasRules {
			if len(result.Triggered) == 0 {
				if err := q.Approve(req.ID, "auto", "all security rules passed"); err != nil {
					log.Warn("auto-approval failed", logs.Err(err))
				} else {
					log.Info("package auto-approved",
						logs.String("package", req.Name),
						logs.String("version", req.Version),
					)
				}
			} else {
				comment := "triggered rules: " + strings.Join(result.Triggered, " ; ")
				_ = q.SetComment(req.ID, comment)
				log.Info("package quarantined (rules)",
					logs.String("package", req.Name),
					logs.String("version", req.Version),
					logs.Int("violations", len(result.Triggered)),
				)
			}
		}
	}
}

// resumePendingScans restarts at startup any scans that were interrupted or errored.
// Packages with no entry in security_scans, scan_status="scanning" (process killed
// mid-scan) or scan_status="error" are resubmitted to the scan hook.
// A 500ms delay between each launch avoids overwhelming external APIs.
func resumePendingScans(q *core.QuarantineStore, log logs.Logger) {
	if q.OnEnqueue == nil {
		return
	}
	pending, err := q.ListNeedingScan()
	if err != nil {
		log.Warn("scan resume: cannot list packages", logs.Err(err))
		return
	}
	if len(pending) == 0 {
		return
	}
	log.Info("resuming interrupted or errored scans", logs.Int("count", len(pending)))
	for _, req := range pending {
		r := req
		go q.OnEnqueue(r)
		time.Sleep(500 * time.Millisecond)
	}
}
