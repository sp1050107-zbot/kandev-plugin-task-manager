package main

import (
	"strings"
	"testing"
)

// Every secret in this file is synthetic. None of them is, or was ever, a
// real credential. They are assembled at runtime (rather than written as
// literals) so repository secret scanners do not flag this file.
var (
	zeros         = strings.Repeat("0", 28)
	fakeOpenAI    = "sk" + "-test-" + zeros
	fakeAnthropic = "sk" + "-ant-api03-EXAMPLE" + zeros
	fakeGHP       = "ghp" + "_EXAMPLE" + zeros
	fakeGHO       = "gho" + "_EXAMPLE" + zeros
	fakeGHS       = "ghs" + "_EXAMPLE" + zeros
	fakeGHPat     = "github" + "_pat_11EXAMPLE" + zeros + "_" + zeros
	fakeSlack     = "xo" + "xb-000000000000-000000000000-EXAMPLEEXAMPLE"
	fakeAWS       = "AK" + "IAEXAMPLE000000000"
	fakeGoogle    = "ya" + "29.EXAMPLE-" + zeros
	fakeJWT       = "ey" + "JhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiJleGFtcGxlIn0" + ".c2lnbmF0dXJlLWV4YW1wbGU"
	fakeSecret    = "hunter2-EXAMPLE"
)

func TestRedactCommand(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// Sensitive flags, --flag=value form.
		{"api-key equals", "tool --api-key=" + fakeSecret + " run", "tool --api-key=[REDACTED] run"},
		{"token equals", "tool --token=" + fakeSecret, "tool --token=[REDACTED]"},
		{"single dash equals", "tool -password=" + fakeSecret, "tool -password=[REDACTED]"},
		{"uppercase flag equals", "tool --API-KEY=" + fakeSecret, "tool --API-KEY=[REDACTED]"},
		{"camelCase flag equals", "tool --accessToken=" + fakeSecret, "tool --accessToken=[REDACTED]"},
		{"snake flag equals", "tool --client_secret=" + fakeSecret, "tool --client_secret=[REDACTED]"},

		// Sensitive flags, --flag value form.
		{"token space", "tool --token " + fakeSecret + " --verbose", "tool --token [REDACTED] --verbose"},
		{"secret space", "tool --secret " + fakeSecret, "tool --secret [REDACTED]"},
		{"password space", "tool --password " + fakeSecret, "tool --password [REDACTED]"},
		{"passwd space", "tool --passwd " + fakeSecret, "tool --passwd [REDACTED]"},
		{"apikey space", "tool --apikey " + fakeSecret, "tool --apikey [REDACTED]"},
		{"key space", "tool --key " + fakeSecret, "tool --key [REDACTED]"},
		{"auth space", "tool --auth " + fakeSecret, "tool --auth [REDACTED]"},
		{"bearer space", "tool --bearer " + fakeSecret, "tool --bearer [REDACTED]"},
		{"credential space", "tool --credential " + fakeSecret, "tool --credential [REDACTED]"},
		{"credentials space", "tool --credentials " + fakeSecret, "tool --credentials [REDACTED]"},
		{"cookie space", "tool --cookie " + fakeSecret, "tool --cookie [REDACTED]"},
		{"session space", "tool --session " + fakeSecret, "tool --session [REDACTED]"},
		{"mixed case space", "tool --Github-Token " + fakeSecret, "tool --Github-Token [REDACTED]"},
		{"sensitive flag then flag", "tool --no-auth --port 3000", "tool --no-auth --port 3000"},

		// Short password flags for tools known to take one.
		{"sshpass -p", "sshpass -p " + fakeSecret + " ssh host", "sshpass -p [REDACTED] ssh host"},
		{"mysql -pSECRET", "/usr/bin/mysql -u root -p" + fakeSecret + " db", "/usr/bin/mysql -u root -p[REDACTED] db"},
		{"curl -u user:pass", "curl -u alice:" + fakeSecret + " https://example.com", "curl -u alice:[REDACTED] https://example.com"},

		// Headers.
		{"authorization bearer", "curl -H Authorization: Bearer " + fakeSecret + " https://example.com",
			"curl -H Authorization: Bearer [REDACTED] https://example.com"},
		{"authorization basic lowercase", "curl -H authorization: basic " + fakeSecret, "curl -H authorization: basic [REDACTED]"},
		{"authorization raw", "curl -H Authorization: " + fakeSecret, "curl -H Authorization: [REDACTED]"},
		{"x-api-key header", "curl -H X-Api-Key: " + fakeSecret, "curl -H X-Api-Key: [REDACTED]"},
		{"bare bearer", "tool Bearer " + fakeSecret, "tool Bearer [REDACTED]"},

		// URLs.
		{"url userinfo", "git clone https://alice:" + fakeSecret + "@example.com/r.git",
			"git clone https://alice:[REDACTED]@example.com/r.git"},
		{"url token query", "curl https://example.com/a?token=" + fakeSecret + "&page=2",
			"curl https://example.com/a?token=[REDACTED]&page=2"},
		{"url access_token query", "curl https://example.com/a?page=2&access_token=" + fakeSecret,
			"curl https://example.com/a?page=2&access_token=[REDACTED]"},
		{"url key query", "curl https://example.com/a?key=" + fakeSecret + "#frag",
			"curl https://example.com/a?key=[REDACTED]#frag"},
		{"url api_key query uppercase", "curl https://example.com/a?API_KEY=" + fakeSecret,
			"curl https://example.com/a?API_KEY=[REDACTED]"},

		// Environment-assignment prefixes.
		{"env prefix", "GITHUB_TOKEN=" + fakeSecret + " gh pr list", "GITHUB_TOKEN=[REDACTED] gh pr list"},
		{"env via env", "env AWS_SECRET_ACCESS_KEY=" + fakeSecret + " aws s3 ls", "env AWS_SECRET_ACCESS_KEY=[REDACTED] aws s3 ls"},
		{"env glued name", "PGPASSWORD=" + fakeSecret + " psql", "PGPASSWORD=[REDACTED] psql"},

		// Well-known token shapes, wherever they appear.
		{"openai sk", "tool " + fakeOpenAI, "tool [REDACTED]"},
		{"anthropic sk-ant", "tool " + fakeAnthropic, "tool [REDACTED]"},
		{"ghp", "tool " + fakeGHP, "tool [REDACTED]"},
		{"gho", "tool " + fakeGHO, "tool [REDACTED]"},
		{"ghs", "tool " + fakeGHS, "tool [REDACTED]"},
		{"github_pat", "tool " + fakeGHPat, "tool [REDACTED]"},
		{"slack", "tool " + fakeSlack, "tool [REDACTED]"},
		{"aws access key id", "tool " + fakeAWS, "tool [REDACTED]"},
		{"google ya29", "tool " + fakeGoogle, "tool [REDACTED]"},
		{"jwt", "tool " + fakeJWT, "tool [REDACTED]"},
		{"token in positional arg", "tool login " + fakeGHP + " --verbose", "tool login [REDACTED] --verbose"},
		{"token inside url userinfo", "git clone https://" + fakeGHP + "@example.com/r.git",
			"git clone https://[REDACTED]@example.com/r.git"},

		// Negative cases: ordinary commands must come through untouched.
		{"node app", "node /path/app.js --port 3000", "node /path/app.js --port 3000"},
		{"claude model", "claude --model opus", "claude --model opus"},
		{"max tokens", "claude --max-tokens 4096 --model opus", "claude --max-tokens 4096 --model opus"},
		{"author flag", "git commit --author bob -m msg", "git commit --author bob -m msg"},
		{"keep alive", "server --keep-alive 30", "server --keep-alive 30"},
		{"mkdir -p", "mkdir -p src/pkg", "mkdir -p src/pkg"},
		{"ssh -p port", "ssh -p 22 host", "ssh -p 22 host"},
		{"plain url", "curl https://example.com/a?page=2&sort=asc", "curl https://example.com/a?page=2&sort=asc"},
		{"ssh userinfo no password", "git clone ssh://git@example.com/r.git", "git clone ssh://git@example.com/r.git"},
		{"harmless env", "NODE_ENV=production node app.js", "NODE_ENV=production node app.js"},
		{"go test", "go test -count=1 ./...", "go test -count=1 ./..."},
		{"short sk word", "tool sk-short", "tool sk-short"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactCommand(tc.in); got != tc.want {
				t.Errorf("redactCommand(%q)\n got  %q\n want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRedactCommandIsIdempotent(t *testing.T) {
	in := "GITHUB_TOKEN=" + fakeGHP + " tool --token " + fakeSecret + " https://a:" + fakeSecret + "@x.test/?key=" + fakeSecret
	once := redactCommand(in)
	if twice := redactCommand(once); twice != once {
		t.Errorf("not idempotent:\n once  %q\n twice %q", once, twice)
	}
	if strings.Contains(once, fakeSecret) || strings.Contains(once, fakeGHP) {
		t.Errorf("secret survived: %q", once)
	}
}

// Redaction must run before truncation: a secret straddling the 160-byte cut
// would otherwise survive as a prefix the pattern no longer recognizes.
func TestDisplayCommandRedactsBeforeTruncating(t *testing.T) {
	prefix := "tool " + strings.Repeat("a", maxCommandLen-20) + " "
	got := displayCommand(prefix + fakeGHP)
	if strings.Contains(got, "EXAMPLE") {
		t.Errorf("token prefix leaked through truncation: %q", got)
	}
	if len(got) > maxCommandLen+len("…") {
		t.Errorf("displayCommand did not truncate: %d bytes", len(got))
	}
}

func TestParsePSLineRedactsCommand(t *testing.T) {
	line := "  42     1  2048   0:01.50 Wed Aug 20 12:00:00 2026 /usr/bin/tool --api-key=" + fakeSecret
	sample, ok := parsePSLine(line)
	if !ok {
		t.Fatal("parsePSLine rejected a valid row")
	}
	if sample.Command != "/usr/bin/tool --api-key=[REDACTED]" {
		t.Errorf("Command = %q", sample.Command)
	}
}
