package config

// Config is the root structure loaded from config.yaml (or MULTIREPO_* environment variables).
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Proxy    ProxyConfig    `mapstructure:"proxy"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Security SecurityConfig `mapstructure:"security"`
	Drivers  DriversConfig  `mapstructure:"drivers"`
}

// ─────────────────────────────────────────────
// Security
// ─────────────────────────────────────────────

// SecurityConfig configures the vulnerability scanners queried on each new quarantine entry.
type SecurityConfig struct {
	OSV      OSVConfig      `mapstructure:"osv"`
	NVD      NVDConfig      `mapstructure:"nvd"`
	Sonatype SonatypeConfig `mapstructure:"sonatype"`
	EPSS     EPSSConfig     `mapstructure:"epss"`
}

// OSVConfig configures the OSV scanner (https://osv.dev).
type OSVConfig struct {
	// Enabled : enable OSV scanning (default: true).
	Enabled bool `mapstructure:"enabled"`
	// Timeout : maximum time per request (default: "10s").
	Timeout string `mapstructure:"timeout"`
}

// NVDConfig configures the NVD NIST scanner (https://nvd.nist.gov).
type NVDConfig struct {
	// Enabled : enable NVD scanning (default: true).
	Enabled bool `mapstructure:"enabled"`
	// APIKey : NVD API key — optional but recommended (rate limit 50 req/30s vs 5 without key).
	// Env var: MULTIREPO_SECURITY_NVD_API_KEY
	APIKey string `mapstructure:"api_key"`
	// Timeout : maximum time per request (default: "15s").
	Timeout string `mapstructure:"timeout"`
}

// EPSSConfig configures EPSS enrichment (Exploit Prediction Scoring System).
type EPSSConfig struct {
	// Enabled : enable EPSS enrichment (default: true).
	// The FIRST.org API is public, no key required, no known rate limit.
	Enabled bool `mapstructure:"enabled"`
	// Timeout : maximum time per request (default: "10s").
	Timeout string `mapstructure:"timeout"`
}

// SonatypeConfig configures the Sonatype OSS Index scanner (https://ossindex.sonatype.org).
type SonatypeConfig struct {
	// Enabled : enable Sonatype OSS Index scanning (default: false).
	Enabled bool `mapstructure:"enabled"`
	// Token : Bearer authentication token (free at ossindex.sonatype.org).
	// Without token: 128 req/24h. With token: 16 req/s.
	// Env var: MULTIREPO_SECURITY_SONATYPE_TOKEN
	Token string `mapstructure:"token"`
	// Timeout : maximum time per request (default: "15s").
	Timeout string `mapstructure:"timeout"`
}

// ─────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────

// LoggingConfig configures log destinations (multi-backend).
// Multiple backends can be active simultaneously.
type LoggingConfig struct {
	// Level : minimum logged level — "debug", "info", "warn", "error" (default: "info")
	Level string `mapstructure:"level"`

	Stdout   StdoutLogConfig   `mapstructure:"stdout"`
	File     FileLogConfig     `mapstructure:"file"`
	Logstash LogstashLogConfig `mapstructure:"logstash"`
	Loki     LokiLogConfig     `mapstructure:"loki"`
}

// StdoutLogConfig enables logging to standard output.
type StdoutLogConfig struct {
	Enabled bool `mapstructure:"enabled"`
	// Format : "text" (colored, human-readable) or "json" (structured).
	Format string `mapstructure:"format"`
}

// FileLogConfig enables logging to a file with automatic rotation.
type FileLogConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
	// MaxSizeMB : maximum size in MB before rotation (default: 100).
	MaxSizeMB int `mapstructure:"max_size_mb"`
	// MaxBackups : number of archived files to keep (default: 5).
	MaxBackups int `mapstructure:"max_backups"`
	// Compress : compress archived files with gzip.
	Compress bool `mapstructure:"compress"`
}

// LogstashLogConfig sends logs as JSON over a TCP or UDP Logstash connection.
type LogstashLogConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Host    string `mapstructure:"host"` // ex: "logstash.corp:5044"
	// Protocol : "tcp" (default) or "udp".
	Protocol string `mapstructure:"protocol"`
}

// LokiLogConfig pushes logs to Grafana Loki via the HTTP API.
type LokiLogConfig struct {
	Enabled bool              `mapstructure:"enabled"`
	URL     string            `mapstructure:"url"`    // ex: "http://loki.corp:3100"
	Labels  map[string]string `mapstructure:"labels"` // static Loki labels
	// BatchSize : maximum number of entries per push (default: 100).
	BatchSize int `mapstructure:"batch_size"`
	// BatchWait : maximum delay before sending even if the batch is incomplete (default: "2s").
	BatchWait string `mapstructure:"batch_wait"`
	// Timeout : HTTP timeout (default: "5s").
	Timeout string `mapstructure:"timeout"`
}

// ─────────────────────────────────────────────
// Auth
// ─────────────────────────────────────────────

// AuthConfig selects and configures the authentication provider for the admin interface.
type AuthConfig struct {
	// Provider : "none" (default), "basic", "oidc" or "ldap".
	Provider string `mapstructure:"provider"`

	// DBPath : path to the SQLite database dedicated to users, groups and rules.
	// If empty, this data is stored in storage.db_path (shared database).
	// Applies to all providers: basic (passwords), ldap/oidc (local groups).
	// Env var: MULTIREPO_AUTH_DB_PATH
	DBPath string `mapstructure:"db_path"`

	// LocalUsers : allow accounts from the local database to log in
	// even when the provider is "ldap" or "oidc".
	// For ldap  : tries LDAP first, then the DB if LDAP rejects.
	// For oidc  : accepts Authorization: Basic from the DB (no OIDC redirect).
	// Env var: MULTIREPO_AUTH_LOCAL_USERS
	LocalUsers bool `mapstructure:"local_users"`

	// SessionSecret signs OIDC session cookies (HMAC-SHA256).
	// Generate with: openssl rand -hex 32
	// Env var: MULTIREPO_AUTH_SESSION_SECRET
	SessionSecret string `mapstructure:"session_secret"`

	BruteForce BruteForceConfig `mapstructure:"brute_force"`
	Basic      BasicAuthConfig  `mapstructure:"basic"`
	OIDC       OIDCAuthConfig   `mapstructure:"oidc"`
	LDAP       LDAPAuthConfig   `mapstructure:"ldap"`
}

// BruteForceConfig enables IP blocking after too many failed authentication attempts.
// Applies to all providers (basic, ldap, oidc).
type BruteForceConfig struct {
	// Enabled : enable brute-force protection (default: true).
	Enabled bool `mapstructure:"enabled"`
	// MaxFailures : number of consecutive failures before blocking (default: 3).
	MaxFailures int `mapstructure:"max_failures"`
	// BlockDuration : duration to block the IP after MaxFailures failures (default: "5m").
	// Env var: MULTIREPO_AUTH_BRUTE_FORCE_BLOCK_DURATION
	BlockDuration string `mapstructure:"block_duration"`
}

// LDAPAuthConfig configures authentication via an LDAP/Active Directory directory.
type LDAPAuthConfig struct {
	// URL of the LDAP server. Ex: "ldap://ldap.corp:389" or "ldaps://ldap.corp:636".
	// Env var: MULTIREPO_AUTH_LDAP_URL
	URL string `mapstructure:"url"`

	// BindDN : DN of the service account used to search for users.
	// Leave empty for anonymous binding.
	// Ex: "cn=svc-multirepo,ou=services,dc=corp,dc=local"
	// Env var: MULTIREPO_AUTH_LDAP_BIND_DN
	BindDN string `mapstructure:"bind_dn"`

	// BindPassword : password of the service account.
	// Recommended env var: MULTIREPO_AUTH_LDAP_BIND_PASSWORD
	BindPassword string `mapstructure:"bind_password"`

	// BaseDN : base DN for user searches.
	// Ex: "ou=users,dc=corp,dc=local"
	BaseDN string `mapstructure:"base_dn"`

	// UserFilter : LDAP filter to locate the user entry.
	// %s is replaced by the provided username. Default: "(uid=%s)".
	// Active Directory: "(sAMAccountName=%s)"
	UserFilter string `mapstructure:"user_filter"`

	// Realm displayed in the browser's HTTP Basic dialog.
	Realm string `mapstructure:"realm"`

	// TLSSkipVerify disables TLS certificate verification (ldaps://).
	// Use only in development.
	TLSSkipVerify bool `mapstructure:"tls_skip_verify"`

	// Timeout : LDAP connection and query timeout (default: "5s").
	Timeout string `mapstructure:"timeout"`

	// GroupBaseDN : base DN for searching the user's groups.
	// If empty, groups are read from the local database (behavior without LDAP mapping).
	// Ex: "ou=groups,dc=corp,dc=local"
	GroupBaseDN string `mapstructure:"group_base_dn"`

	// GroupFilter : LDAP filter to find a user's groups.
	// %s is replaced by the full DN of the user (member, memberOf attribute...).
	// %u is replaced by the username / uid (memberUid, posixGroup attribute).
	// Default: "(member=%s)"
	// Active Directory / memberOf: "(&(objectClass=group)(member=%s))"
	// posixGroup OpenLDAP         : "(memberUid=%u)"
	GroupFilter string `mapstructure:"group_filter"`

	// GroupAttribute : LDAP attribute holding the group name.
	// Default: "cn"
	GroupAttribute string `mapstructure:"group_attribute"`

	// GroupMapping : mapping from LDAP group name to local group name.
	// Only LDAP groups present in this table are forwarded.
	// The local group "admin" grants superadmin rights.
	// Ex:
	//   admins: admin
	//   pkg-approvers: approvers
	GroupMapping map[string]string `mapstructure:"group_mapping"`
}

// BasicAuthConfig configures HTTP Basic authentication.
// The user database is the shared GORM database (storage.db_path).
// An htpasswd file can be added as a supplement.
type BasicAuthConfig struct {
	// Realm displayed in the browser's dialog box.
	Realm string `mapstructure:"realm"`
	// HtpasswdFile : path to an Apache htpasswd file (optional).
	// Supported formats: bcrypt ($2y$/$2a$/$2b$) and SHA1 ({SHA}).
	HtpasswdFile string `mapstructure:"htpasswd_file"`
}

// OIDCAuthConfig configures OpenID Connect authentication.
type OIDCAuthConfig struct {
	// Issuer : base URL of the OIDC provider (must expose /.well-known/openid-configuration).
	// Ex: "https://accounts.google.com", "https://keycloak.corp/realms/myrealm"
	Issuer string `mapstructure:"issuer"`
	// ClientID and ClientSecret are provided by the OIDC provider.
	// Prefer MULTIREPO_AUTH_OIDC_CLIENT_SECRET in production.
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	// RedirectURL must exactly match the callback URI registered with the provider.
	// Ex: "https://proxy.corp:8222/admin/auth/callback"
	RedirectURL string `mapstructure:"redirect_url"`
	// Scopes requested from the provider. Default: ["openid", "email", "profile"].
	Scopes []string `mapstructure:"scopes"`
	// SessionTTL : session validity duration in hours (default: 8).
	SessionTTL int `mapstructure:"session_ttl"`
}

// ProxyConfig configures the outbound HTTP proxy used to reach upstreams.
// Credentials are separated from the URL to ease secret management in containers.
//
// Equivalent environment variables:
//
//	MULTIREPO_PROXY_HTTP      MULTIREPO_PROXY_HTTPS
//	MULTIREPO_PROXY_USERNAME  MULTIREPO_PROXY_PASSWORD
//	MULTIREPO_PROXY_NO_PROXY
type ProxyConfig struct {
	// HTTP and HTTPS : proxy URL without credentials, ex: "http://proxy.corp:3128"
	HTTP  string `mapstructure:"http"`
	HTTPS string `mapstructure:"https"`

	// Username and Password : authentication credentials for the proxy.
	// Injected into the URL at connection time — do not put them in HTTP/HTTPS.
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	// NoProxy : hosts or domains excluded from the proxy, comma-separated.
	// Same format as the NO_PROXY environment variable: "localhost,127.0.0.1,.corp.local"
	NoProxy string `mapstructure:"no_proxy"`
}

type ServerConfig struct {
	// Addr is the listen address, ex: ":8222".
	Addr string    `mapstructure:"addr"`
	TLS  TLSConfig `mapstructure:"tls"`
}

// TLSConfig enables the HTTPS listener.
type TLSConfig struct {
	// Enabled : enable TLS (HTTPS). Requires CertFile and KeyFile.
	Enabled bool `mapstructure:"enabled"`
	// CertFile : path to the PEM certificate (full chain).
	CertFile string `mapstructure:"cert_file"`
	// KeyFile : path to the PEM private key.
	KeyFile string `mapstructure:"key_file"`
}

type StorageConfig struct {
	// CacheDir is the root directory for the disk cache.
	CacheDir string `mapstructure:"cache_dir"`
	// DBPath is the path to the single SQLite database (quarantine, security, auth).
	// Shared across all components and supporting multiple simultaneous instances
	// thanks to WAL mode and a 5-second busy_timeout.
	// Env var: MULTIREPO_STORAGE_DB_PATH
	DBPath string `mapstructure:"db_path"`
}

type DriversConfig struct {
	Apt    AptConfig    `mapstructure:"apt"`
	Docker DockerConfig `mapstructure:"docker"`
	PyPI   PyPIConfig   `mapstructure:"pypi"`
	Go     GoConfig     `mapstructure:"go"`
	CRAN   CRANConfig   `mapstructure:"cran"`
	Npm    NpmConfig    `mapstructure:"npm"`
}

// AptConfig configures the apt/Debian proxy.
type AptConfig struct {
	Enabled      bool      `mapstructure:"enabled"`
	Prefix       string    `mapstructure:"prefix"`
	Upstream     string    `mapstructure:"upstream"`
	AuthRequired bool      `mapstructure:"auth_required"`
	GPG          GPGConfig `mapstructure:"gpg"`
}

// GPGConfig configures GPG verification of .deb packages.
type GPGConfig struct {
	// KeyringDir is the storage directory for imported public keys.
	KeyringDir string `mapstructure:"keyring_dir"`
	// RejectUnsigned rejects .deb packages without a _gpgorigin signature when true.
	RejectUnsigned bool `mapstructure:"reject_unsigned"`
}

// DockerConfig configures the Docker Distribution v2 proxy.
type DockerConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	Prefix       string `mapstructure:"prefix"`
	Upstream     string `mapstructure:"upstream"`
	AuthRequired bool   `mapstructure:"auth_required"`
	// Username and Password are optional (private registry).
	// In containers, prefer MULTIREPO_DRIVERS_DOCKER_USERNAME / _PASSWORD.
	Username string       `mapstructure:"username"`
	Password string       `mapstructure:"password"`
	Cosign   CosignConfig `mapstructure:"cosign"`
}

// CosignConfig configures Cosign (Sigstore) signature verification for Docker images.
// Signatures are stored in the same registry under the tag "<digest>.sig".
type CosignConfig struct {
	// Enabled : enable Cosign signature verification (default: false).
	Enabled bool `mapstructure:"enabled"`

	// PublicKeyFiles : list of paths to PEM public keys (ECDSA P-256 / P-384 / P-521).
	// The signature is valid if it matches at least one key in the list.
	// If empty and Enabled=true, only the presence of the signature is checked (no cryptography).
	// Env var: MULTIREPO_DRIVERS_DOCKER_COSIGN_PUBLIC_KEY_FILES
	PublicKeyFiles []string `mapstructure:"public_key_files"`

	// RequireSignature : if true, any image without a Cosign signature triggers
	// mandatory human validation (default: true when Enabled=true).
	RequireSignature bool `mapstructure:"require_signature"`
}

// PyPIConfig configures the PyPI proxy.
type PyPIConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	Prefix       string `mapstructure:"prefix"`
	Upstream     string `mapstructure:"upstream"`
	AuthRequired bool   `mapstructure:"auth_required"`
}

// GoConfig configures the Go Module Proxy.
type GoConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	Prefix       string `mapstructure:"prefix"`
	Upstream     string `mapstructure:"upstream"`
	AuthRequired bool   `mapstructure:"auth_required"`
}

// CRANConfig configures the CRAN proxy (R packages).
type CRANConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	Prefix       string `mapstructure:"prefix"`
	Upstream     string `mapstructure:"upstream"`
	AuthRequired bool   `mapstructure:"auth_required"`
}

// NpmConfig configures the npm registry proxy.
type NpmConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	Prefix       string `mapstructure:"prefix"`
	Upstream     string `mapstructure:"upstream"`
	AuthRequired bool   `mapstructure:"auth_required"`
}

// Defaults returns a Config with all default values.
// They are applied before reading the YAML file and environment variables,
// allowing the server to start without any configuration file.
func Defaults() Config {
	return Config{
		Server: ServerConfig{
			Addr: ":8222",
		},
		Storage: StorageConfig{
			CacheDir: "/var/cache/multirepo",
			DBPath:   "/var/lib/multirepo/multirepo.db",
		},
		Auth: AuthConfig{
			Provider: "none",
			BruteForce: BruteForceConfig{
				Enabled:       true,
				MaxFailures:   3,
				BlockDuration: "5m",
			},
			Basic: BasicAuthConfig{
				Realm: "multirepo-proxy admin",
			},
			OIDC: OIDCAuthConfig{
				Scopes:     []string{"openid", "email", "profile"},
				SessionTTL: 8,
			},
			LDAP: LDAPAuthConfig{
				UserFilter:     "(uid=%s)",
				Realm:          "multirepo-proxy admin",
				Timeout:        "5s",
				GroupFilter:    "(member=%s)",
				GroupAttribute: "cn",
			},
		},
		Logging: LoggingConfig{
			Level: "info",
			Stdout: StdoutLogConfig{
				Enabled: true,
				Format:  "text",
			},
			File: FileLogConfig{
				MaxSizeMB:  100,
				MaxBackups: 5,
			},
			Logstash: LogstashLogConfig{
				Protocol: "tcp",
			},
			Loki: LokiLogConfig{
				Labels:    map[string]string{"app": "multirepo-proxy"},
				BatchSize: 100,
				BatchWait: "2s",
				Timeout:   "5s",
			},
		},
		Security: SecurityConfig{
			OSV:      OSVConfig{Enabled: true, Timeout: "10s"},
			NVD:      NVDConfig{Enabled: true, Timeout: "15s"},
			Sonatype: SonatypeConfig{Enabled: false, Timeout: "15s"},
			EPSS:     EPSSConfig{Enabled: true, Timeout: "10s"},
		},
		Drivers: DriversConfig{
			Apt: AptConfig{
				Enabled:      true,
				Prefix:       "/ubuntu/",
				Upstream:     "http://archive.ubuntu.com/ubuntu",
				AuthRequired: true,
				GPG: GPGConfig{
					KeyringDir:     "/var/lib/multirepo/keyrings/apt",
					RejectUnsigned: false,
				},
			},
			Docker: DockerConfig{
				Enabled:      true,
				Prefix:       "/v2/",
				Upstream:     "https://registry-1.docker.io",
				AuthRequired: true,
				Cosign: CosignConfig{
					Enabled:          false,
					RequireSignature: true,
					PublicKeyFiles:   []string{},
				},
			},
			PyPI: PyPIConfig{
				Enabled:      true,
				Prefix:       "/pypi/",
				Upstream:     "https://pypi.org",
				AuthRequired: true,
			},
			Go: GoConfig{
				Enabled:      true,
				Prefix:       "/go/",
				Upstream:     "https://proxy.golang.org",
				AuthRequired: true,
			},
			CRAN: CRANConfig{
				Enabled:      true,
				Prefix:       "/cran/",
				Upstream:     "https://cran.r-project.org",
				AuthRequired: true,
			},
			Npm: NpmConfig{
				Enabled:      true,
				Prefix:       "/npm/",
				Upstream:     "https://registry.npmjs.org",
				AuthRequired: true,
			},
		},
	}
}
