package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// composeDir holds the deployment the README tells operators to copy.
func composeDir() string { return filepath.Join("..", "..", "deploy", "docker") }

func readDeployFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(composeDir(), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(raw)
}

// controlTokenPathFromExample returns access.control_token_file as the shipped
// container example configures it. That file is the single source of truth for
// the path; the compose service has to agree with it rather than restate it.
func controlTokenPathFromExample(t *testing.T) string {
	t.Helper()
	var input rawConfig
	if _, err := toml.Decode(readDeployFile(t, "config.example.toml"), &input); err != nil {
		t.Fatalf("container config example does not parse: %v", err)
	}
	return input.Access.ControlTokenFile
}

// The container example sets access.control_token_file, and /healthz answers 401
// whenever a control token is configured: the mutating-auth change exempts read
// paths from *requiring* a token, but it does not exempt them from *checking* one
// that exists. So a compose stack copied from these files probes unauthenticated,
// gets 401, and reports a healthy container as unhealthy until it hits its retry
// limit. The healthcheck must therefore pass -token-file with the same path the
// config example names.
func TestComposeHealthcheckSendsTheConfiguredControlToken(t *testing.T) {
	tokenPath := controlTokenPathFromExample(t)
	if tokenPath == "" {
		t.Skip("container example configures no control token; nothing to authenticate")
	}

	compose := readDeployFile(t, "docker-compose.yml")
	test, ok := composeHealthcheckTest(compose)
	if !ok {
		t.Fatal("compose service defines no healthcheck test")
	}

	if !containsArg(test, "-token-file") {
		t.Errorf("compose healthcheck does not pass -token-file, so the probe is\n"+
			"unauthenticated against a control API that requires %s; got %q", tokenPath, test)
	}
	if !containsArg(test, tokenPath) {
		t.Errorf("compose healthcheck token path does not match the config example.\n"+
			"config.example.toml: %s\nhealthcheck test:    %q", tokenPath, test)
	}
}

// A -token-file the container cannot read is worse than none: the probe fails
// with a read error and the container is marked unhealthy while it serves fine.
// The secret has to be mounted at the very path the config example names.
func TestComposeMountsTheControlTokenReadOnly(t *testing.T) {
	tokenPath := controlTokenPathFromExample(t)
	if tokenPath == "" {
		t.Skip("container example configures no control token; nothing to mount")
	}

	compose := readDeployFile(t, "docker-compose.yml")
	mount, ok := composeMountFor(compose, tokenPath)
	if !ok {
		t.Fatalf("compose mounts nothing at %s, so both serve and the healthcheck\n"+
			"fail to read the control token the config example requires", tokenPath)
	}
	if !strings.HasSuffix(mount, ":ro") {
		t.Errorf("control token mount %q is not read-only", mount)
	}
}

// The prerequisites comment is the checklist an operator follows before the first
// `up -d`. A required secret missing from it produces a container that starts and
// then fails its health check for reasons the comment does not explain.
func TestComposePrerequisitesMentionTheControlToken(t *testing.T) {
	tokenPath := controlTokenPathFromExample(t)
	if tokenPath == "" {
		t.Skip("container example configures no control token")
	}

	header, _, found := strings.Cut(readDeployFile(t, "docker-compose.yml"), "\nname:")
	if !found {
		t.Fatal("compose file has no header comment block")
	}
	if !strings.Contains(header, filepath.Base(tokenPath)) {
		t.Errorf("compose prerequisites do not list %s among the files to create:\n%s",
			filepath.Base(tokenPath), header)
	}
}

// composeHealthcheckTest extracts the healthcheck test entry, ignoring comments so
// that a commented-out example cannot satisfy a check about the live command.
func composeHealthcheckTest(compose string) (string, bool) {
	lines := strings.Split(compose, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "healthcheck:" {
			start = i
			break
		}
	}
	if start < 0 {
		return "", false
	}
	indent := len(lines[start]) - len(strings.TrimLeft(lines[start], " "))

	var test strings.Builder
	inTest := false
	for _, line := range lines[start+1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lineIndent := len(line) - len(strings.TrimLeft(line, " "))
		if lineIndent <= indent {
			break
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "test:") {
			inTest = true
			test.WriteString(strings.TrimPrefix(trimmed, "test:"))
			continue
		}
		// Any other key at the healthcheck level ends the test value.
		if inTest && lineIndent <= indent+2 && strings.Contains(trimmed, ":") &&
			!strings.HasPrefix(trimmed, "-") && !strings.HasPrefix(trimmed, "[") {
			break
		}
		if inTest {
			test.WriteString(" " + trimmed)
		}
	}
	if !inTest {
		return "", false
	}
	return strings.TrimSpace(test.String()), true
}

// composeMountFor finds an uncommented volume entry whose container path is target.
func composeMountFor(compose, target string) (string, bool) {
	for _, line := range strings.Split(compose, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		entry := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		parts := strings.Split(entry, ":")
		if len(parts) < 2 {
			continue
		}
		if parts[1] == target {
			return entry, true
		}
	}
	return "", false
}

// containsArg reports whether the extracted test command carries the argument as
// its own quoted token, so that a substring of a longer path cannot match.
func containsArg(test, arg string) bool {
	for _, field := range strings.FieldsFunc(test, func(r rune) bool {
		return r == '[' || r == ']' || r == ',' || r == '"' || r == ' '
	}) {
		if field == arg {
			return true
		}
	}
	return false
}
