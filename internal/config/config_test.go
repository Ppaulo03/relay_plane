package config

import (
	"strings"
	"testing"
)

func valid() Config {
	return Config{DatabaseURL: "postgres://x", BlobEndpoint: "minio:9000", BlobAccessKey: "a", BlobSecretKey: "s", WebhookSecret: "0123456789abcdef",
		Nodes: []Node{{ID: "node-01", Provider: "evolution-v2", Endpoint: "http://n1:8080", APIKey: "k1", Capacity: 10}}}
}

func TestValidateRequiresProviderNodesForEveryRole(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(*Config){
		"no nodes":       func(c *Config) { c.Nodes = nil },
		"empty endpoint": func(c *Config) { c.Nodes[0].Endpoint = "" },
		"empty api key":  func(c *Config) { c.Nodes[0].APIKey = "" },
		"zero capacity":  func(c *Config) { c.Nodes[0].Capacity = 0 },
		"empty provider": func(c *Config) { c.Nodes[0].Provider = "" },
		"duplicate node": func(c *Config) { c.Nodes = append(c.Nodes, c.Nodes[0]) },
		"missing secret": func(c *Config) { c.WebhookSecret = "" },
		"missing db":     func(c *Config) { c.DatabaseURL = "" },
		"short prod key": func(c *Config) { c.Env, c.WebhookSecret = "production", "short" },
	}
	for name, mut := range cases {
		c := valid()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestValidateErrorsNeverEchoSecrets(t *testing.T) {
	c := valid()
	c.Nodes[0].Capacity = 0
	c.Nodes[0].APIKey = "super-secret-key"
	if err := c.Validate(); err == nil || strings.Contains(err.Error(), "super-secret-key") {
		t.Fatalf("api key leaked in error: %v", err)
	}
}

func TestLoadDefaultsNodeProviderAndAllowedVersions(t *testing.T) {
	t.Setenv("PROVIDER_NODES", `[{"id":"n1","endpoint":"http://n","api_key":"k","capacity":5}]`)
	t.Setenv("EVOLUTION_ALLOWED_VERSIONS", "2.3.7,2.4.0")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Nodes[0].Provider != "evolution-v2" || len(c.EvolutionAllowedVersions) != 2 {
		t.Fatalf("%+v", c)
	}
}

func TestWebhookDestinationsAreStrictOutsideDevelopment(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.WebhooksAllowPrivate || c.WebhooksAllowInsecure {
		t.Fatalf("production must default to https + public destinations only: %+v", c)
	}
	t.Setenv("APP_ENV", "development")
	if c, _ = Load(); !c.WebhooksAllowPrivate || !c.WebhooksAllowInsecure {
		t.Errorf("development lets the agent run on a private docker network over http: %+v", c)
	}
	t.Setenv("APP_ENV", "production")
	t.Setenv("WEBHOOKS_ALLOW_PRIVATE_DESTINATIONS", "true")
	if c, _ = Load(); !c.WebhooksAllowPrivate {
		t.Error("an operator can opt in explicitly")
	}
}

func TestTenantWebhookAndIdempotencySettings(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.IdempotencyTTL.Hours() != 24 || c.WebhooksMaxPerTenant != 10 || c.WebhookDeliveryWorkers != 8 || c.WebhookDeliveredRetention.Hours() != 7*24 {
		t.Errorf("defaults: %+v", c)
	}
	v := valid()
	v.IdempotencyTTL = 5 * 1e9 // 5s
	if err := v.Validate(); err == nil {
		t.Error("an idempotency window under a minute defeats safe client retries")
	}
	v = valid()
	v.Env, v.SubscriptionSecret = "production", "short"
	if err := v.Validate(); err == nil || strings.Contains(err.Error(), "short") {
		t.Errorf("a short subscription secret is rejected without being echoed: %v", err)
	}
}

func TestAdminKeyRotationSettings(t *testing.T) {
	// placeholder keys of the right length (not secrets): one letter repeated
	newKey, oldKey := strings.Repeat("n", 16), strings.Repeat("o", 16)
	ok := map[string]func(*Config){
		"no admin key":           func(c *Config) {},
		"rotation in progress":   func(c *Config) { c.AdminAPIKey, c.AdminAPIKeyPrevious = newKey, oldKey },
		"long key in production": func(c *Config) { c.Env, c.AdminAPIKey = "production", newKey },
	}
	for name, mut := range ok {
		c := valid()
		mut(&c)
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]func(*Config){
		"short admin key in production": func(c *Config) { c.Env, c.AdminAPIKey = "production", "short" },
		"short previous key in production": func(c *Config) {
			c.Env, c.AdminAPIKey, c.AdminAPIKeyPrevious = "production", newKey, "short"
		},
		"previous key without a new one": func(c *Config) { c.AdminAPIKeyPrevious = oldKey },
		"previous equal to the current":  func(c *Config) { c.AdminAPIKey, c.AdminAPIKeyPrevious = newKey, newKey },
	}
	for name, mut := range bad {
		c := valid()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if c.AdminAPIKey != "" && strings.Contains(err.Error(), c.AdminAPIKey) {
			t.Errorf("%s: the error echoes the key", name)
		}
	}
}

// /metrics is unauthenticated: production keeps it off the gateway's public port (it stays on OPS_PORT).
func TestMetricsLeaveThePublicPortInProduction(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	if c, _ := Load(); c.MetricsOnAPIPort {
		t.Error("production must not serve /metrics on the public API port by default")
	}
	t.Setenv("APP_ENV", "development")
	if c, _ := Load(); !c.MetricsOnAPIPort {
		t.Error("development keeps /metrics on the API port (local tooling scrapes it there)")
	}
	t.Setenv("APP_ENV", "production")
	t.Setenv("METRICS_ON_API_PORT", "true")
	if c, _ := Load(); !c.MetricsOnAPIPort {
		t.Error("an operator can opt in explicitly")
	}
}
