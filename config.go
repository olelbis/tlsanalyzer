package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type fileConfig struct {
	Host           *string                      `json:"host,omitempty"`
	Port           *string                      `json:"port,omitempty"`
	SNI            *string                      `json:"sni,omitempty"`
	Cert           *bool                        `json:"cert,omitempty"`
	CheckCert      *bool                        `json:"checkcert,omitempty"`
	Timeout        *int                         `json:"timeout,omitempty"`
	Output         *string                      `json:"output,omitempty"`
	MinVersion     *string                      `json:"min_version,omitempty"`
	Markdown       *string                      `json:"markdown,omitempty"`
	SARIF          *string                      `json:"sarif,omitempty"`
	JUnit          *string                      `json:"junit,omitempty"`
	ForceCiphers   *bool                        `json:"force_ciphers,omitempty"`
	SkipVerify     *bool                        `json:"skip_verify,omitempty"`
	JSON           *bool                        `json:"json,omitempty"`
	NoClear        *bool                        `json:"no_clear,omitempty"`
	Compact        *bool                        `json:"compact,omitempty"`
	Policy         *string                      `json:"policy,omitempty"`
	FailOn         *string                      `json:"fail_on,omitempty"`
	RequireTLS     *string                      `json:"require_tls,omitempty"`
	ForbidTLS      *string                      `json:"forbid_tls,omitempty"`
	RequireALPN    *string                      `json:"require_alpn,omitempty"`
	ForbidALPN     *string                      `json:"forbid_alpn,omitempty"`
	MinCertKeyBits *int                         `json:"min_cert_key_bits,omitempty"`
	MinCertDays    *int                         `json:"min_cert_days,omitempty"`
	Target         *string                      `json:"target,omitempty"`
	Profile        *string                      `json:"profile,omitempty"`
	TargetsFile    *string                      `json:"targets_file,omitempty"`
	Concurrency    *int                         `json:"concurrency,omitempty"`
	Retries        *int                         `json:"retries,omitempty"`
	RetryBackoff   *int                         `json:"retry_backoff,omitempty"`
	Targets        map[string]fileTarget        `json:"targets,omitempty"`
	Profiles       map[string]filePolicyProfile `json:"profiles,omitempty"`
}

type fileTarget struct {
	Host *string `json:"host,omitempty"`
	Port *string `json:"port,omitempty"`
	SNI  *string `json:"sni,omitempty"`
}

type filePolicyProfile struct {
	Policy         *string `json:"policy,omitempty"`
	FailOn         *string `json:"fail_on,omitempty"`
	RequireTLS     *string `json:"require_tls,omitempty"`
	ForbidTLS      *string `json:"forbid_tls,omitempty"`
	RequireALPN    *string `json:"require_alpn,omitempty"`
	ForbidALPN     *string `json:"forbid_alpn,omitempty"`
	MinCertKeyBits *int    `json:"min_cert_key_bits,omitempty"`
	MinCertDays    *int    `json:"min_cert_days,omitempty"`
}

type cliInputError struct {
	err error
}

func (e cliInputError) Error() string {
	return e.err.Error()
}

func (e cliInputError) Unwrap() error {
	return e.err
}

func loadFileConfig(path string) (fileConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return fileConfig{}, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	var cfg fileConfig
	if err := decoder.Decode(&cfg); err != nil {
		return fileConfig{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fileConfig{}, fmt.Errorf("config must contain a single JSON object")
	}
	return cfg, nil
}

func applyFileConfig(cfg *cliConfig, file fileConfig, cliTarget, cliProfile string) error {
	applyFileConfigValues(cfg, file)

	targetName := stringValue(file.Target)
	if cliTarget != "" {
		targetName = cliTarget
	}
	if targetName != "" {
		target, ok := file.Targets[targetName]
		if !ok {
			return fmt.Errorf("config target %q is not defined", targetName)
		}
		applyFileTarget(cfg, target)
		cfg.targetName = targetName
	}

	profileName := stringValue(file.Profile)
	if cliProfile != "" {
		profileName = cliProfile
	}
	if profileName != "" {
		profile, ok := file.Profiles[profileName]
		if !ok {
			return fmt.Errorf("config profile %q is not defined", profileName)
		}
		applyPolicyProfile(cfg, profile)
		cfg.profileName = profileName
	}
	return nil
}

func applyFileConfigValues(cfg *cliConfig, file fileConfig) {
	applyString(&cfg.host, file.Host)
	applyString(&cfg.port, file.Port)
	applyString(&cfg.sni, file.SNI)
	applyBool(&cfg.certChain, file.Cert)
	applyBool(&cfg.checkCertExpiry, file.CheckCert)
	applyInt(&cfg.timeout, file.Timeout)
	applyString(&cfg.outputFile, file.Output)
	applyString(&cfg.minVersionStr, file.MinVersion)
	applyString(&cfg.outputMarkdown, file.Markdown)
	applyString(&cfg.outputSARIF, file.SARIF)
	applyString(&cfg.outputJUnit, file.JUnit)
	applyBool(&cfg.forceCiphers, file.ForceCiphers)
	applyBool(&cfg.skipVerify, file.SkipVerify)
	applyBool(&cfg.outputJSON, file.JSON)
	applyBool(&cfg.noClear, file.NoClear)
	applyBool(&cfg.compact, file.Compact)
	applyString(&cfg.policy, file.Policy)
	applyString(&cfg.failOn, file.FailOn)
	applyString(&cfg.requireTLS, file.RequireTLS)
	applyString(&cfg.forbidTLS, file.ForbidTLS)
	applyString(&cfg.requireALPN, file.RequireALPN)
	applyString(&cfg.forbidALPN, file.ForbidALPN)
	applyInt(&cfg.minCertKeyBits, file.MinCertKeyBits)
	applyInt(&cfg.minCertDays, file.MinCertDays)
	applyString(&cfg.targetsFile, file.TargetsFile)
	applyInt(&cfg.concurrency, file.Concurrency)
	applyInt(&cfg.retries, file.Retries)
	applyInt(&cfg.retryBackoff, file.RetryBackoff)
}

func applyFileTarget(cfg *cliConfig, target fileTarget) {
	applyString(&cfg.host, target.Host)
	applyString(&cfg.port, target.Port)
	applyString(&cfg.sni, target.SNI)
}

func applyPolicyProfile(cfg *cliConfig, profile filePolicyProfile) {
	applyString(&cfg.policy, profile.Policy)
	applyString(&cfg.failOn, profile.FailOn)
	applyString(&cfg.requireTLS, profile.RequireTLS)
	applyString(&cfg.forbidTLS, profile.ForbidTLS)
	applyString(&cfg.requireALPN, profile.RequireALPN)
	applyString(&cfg.forbidALPN, profile.ForbidALPN)
	applyInt(&cfg.minCertKeyBits, profile.MinCertKeyBits)
	applyInt(&cfg.minCertDays, profile.MinCertDays)
}

func overlayExplicitCLIValues(dst *cliConfig, src cliConfig, explicit map[string]bool) {
	if explicit["host"] {
		dst.host = src.host
	}
	if explicit["port"] {
		dst.port = src.port
	}
	if explicit["sni"] {
		dst.sni = src.sni
	}
	if explicit["cert"] {
		dst.certChain = src.certChain
	}
	if explicit["checkcert"] {
		dst.checkCertExpiry = src.checkCertExpiry
	}
	if explicit["timeout"] {
		dst.timeout = src.timeout
	}
	if explicit["output"] {
		dst.outputFile = src.outputFile
	}
	if explicit["min-version"] {
		dst.minVersionStr = src.minVersionStr
	}
	if explicit["markdown"] {
		dst.outputMarkdown = src.outputMarkdown
	}
	if explicit["sarif"] {
		dst.outputSARIF = src.outputSARIF
	}
	if explicit["junit"] {
		dst.outputJUnit = src.outputJUnit
	}
	if explicit["force-ciphers"] {
		dst.forceCiphers = src.forceCiphers
	}
	if explicit["skip-verify"] {
		dst.skipVerify = src.skipVerify
	}
	if explicit["json"] {
		dst.outputJSON = src.outputJSON
	}
	if explicit["no-clear"] {
		dst.noClear = src.noClear
	}
	if explicit["compact"] {
		dst.compact = src.compact
	}
	if explicit["version"] {
		dst.showVersion = src.showVersion
	}
	if explicit["policy"] {
		dst.policy = src.policy
	}
	if explicit["fail-on"] {
		dst.failOn = src.failOn
	}
	if explicit["require-tls"] {
		dst.requireTLS = src.requireTLS
	}
	if explicit["forbid-tls"] {
		dst.forbidTLS = src.forbidTLS
	}
	if explicit["require-alpn"] {
		dst.requireALPN = src.requireALPN
	}
	if explicit["forbid-alpn"] {
		dst.forbidALPN = src.forbidALPN
	}
	if explicit["min-cert-key-bits"] {
		dst.minCertKeyBits = src.minCertKeyBits
	}
	if explicit["min-cert-days"] {
		dst.minCertDays = src.minCertDays
	}
	if explicit["target"] {
		dst.targetName = src.targetName
	}
	if explicit["profile"] {
		dst.profileName = src.profileName
	}
	if explicit["targets-file"] {
		dst.targetsFile = src.targetsFile
	}
	if explicit["concurrency"] {
		dst.concurrency = src.concurrency
	}
	if explicit["retries"] {
		dst.retries = src.retries
	}
	if explicit["retry-backoff"] {
		dst.retryBackoff = src.retryBackoff
	}
	dst.configPath = src.configPath
}

func defaultCLIConfig(stderr io.Writer) cliConfig {
	var cfg cliConfig
	newFlagSet(&cfg, stderr)
	return cfg
}

func applyString(dst *string, value *string) {
	if value != nil {
		*dst = *value
	}
}

func applyBool(dst *bool, value *bool) {
	if value != nil {
		*dst = *value
	}
}

func applyInt(dst *int, value *int) {
	if value != nil {
		*dst = *value
	}
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
