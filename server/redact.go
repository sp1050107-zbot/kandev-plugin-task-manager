package main

import (
	"regexp"
	"strings"
)

// redacted replaces every secret value the plugin recognizes in a command
// line. The flag, header or variable name around it is kept so the row stays
// readable ("--api-key=[REDACTED]" still says what the process was given).
const redacted = "[REDACTED]"

// displayCommand is the only way a command line may enter procSample.Command.
// Redaction runs first: truncating first could cut a secret in half and leave
// a prefix too short for any pattern to recognize.
func displayCommand(s string) string {
	return truncateCommand(redactCommand(s))
}

// tokenShapes match credentials by their well-known formats, wherever they
// appear in the line (a positional argument, inside a URL, glued to a flag).
var tokenShapes = []*regexp.Regexp{
	// OpenAI / Anthropic style keys (sk-..., sk-proj-..., sk-ant-...).
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),
	// GitHub classic and fine-grained tokens.
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
	// Slack tokens.
	regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`),
	// AWS access key ids (long-term and STS).
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	// Google OAuth access tokens.
	regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}`),
	// JWTs: three base64url segments, the first a JSON header ("eyJ").
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`),
}

var (
	// scheme://user:password@host — keep the user, drop the password.
	urlUserinfo = regexp.MustCompile(`(://[^/\s:@]+):[^/\s@]+@`)
	// ?token=... / &access_token=... / ?key=... and similar query parameters.
	urlSecretParam = regexp.MustCompile(`(?i)([?&][a-z0-9_.-]*(?:token|key|secret|password|passwd|auth|signature|credential|session)[a-z0-9_.-]*=)[^&\s#]+`)

	envAssignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.+)$`)
	flagWithValue = regexp.MustCompile(`^(--?[A-Za-z][A-Za-z0-9_.-]*)=(.+)$`)
	bareFlag      = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9_.-]*$`)
	headerName    = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*):$`)
	nameSegments  = regexp.MustCompile(`[-_.]+`)
)

// sensitiveSegments are flag / variable / header name segments that mark the
// accompanying value as a secret. Matching is per segment rather than by
// substring so that e.g. --max-tokens and --author are left alone.
var sensitiveSegments = map[string]bool{
	"token": true, "secret": true, "secrets": true,
	"password": true, "passwd": true, "pass": true,
	"key": true, "apikey": true,
	"auth": true, "authorization": true, "bearer": true,
	"credential": true, "credentials": true,
	"cookie": true, "cookies": true, "session": true,
}

// sensitiveSuffixes catch glued names: --accessToken, PGPASSWORD,
// clientsecret, oauth.
var sensitiveSuffixes = []string{
	"token", "secret", "password", "passwd", "apikey", "key", "credential", "credentials", "auth",
}

func sensitiveName(name string) bool {
	name = strings.ToLower(strings.TrimLeft(name, "-"))
	for _, seg := range nameSegments.Split(name, -1) {
		if seg == "" {
			continue
		}
		if sensitiveSegments[seg] {
			return true
		}
		for _, suffix := range sensitiveSuffixes {
			if strings.HasSuffix(seg, suffix) {
				return true
			}
		}
	}
	return false
}

// authSchemes may sit between "Authorization:" and the credential itself.
var authSchemes = map[string]bool{"bearer": true, "basic": true, "token": true, "digest": true}

// Program-specific short flags whose next argument is a password. Generic
// single-letter flags (-p, -u) mean something harmless for most tools
// (mkdir -p, ssh -p 22), so they are only treated as secrets for these.
var (
	passwordNextProgs  = map[string]bool{"sshpass": true}
	gluedPasswordProgs = map[string]bool{"mysql": true, "mysqldump": true, "mysqladmin": true, "mariadb": true, "mariadb-dump": true}
	userPassProgs      = map[string]bool{"curl": true, "wget": true}
	wrapperProgs       = map[string]bool{"env": true, "sudo": true, "nohup": true, "exec": true, "command": true}
)

func looksLikeFlag(tok string) bool {
	return len(tok) > 1 && tok[0] == '-'
}

// redactCommand masks secrets in a display command line. It errs toward
// over-redaction: a hidden harmless argument costs readability, a shown
// credential costs the credential.
func redactCommand(s string) string {
	if s == "" {
		return s
	}
	for _, re := range tokenShapes {
		s = re.ReplaceAllString(s, redacted)
	}
	s = urlUserinfo.ReplaceAllString(s, "$1:"+redacted+"@")
	s = urlSecretParam.ReplaceAllString(s, "$1"+redacted)
	return redactTokens(s)
}

// redactTokens walks the whitespace-separated words of s, preserving the
// original separators, and masks values introduced by a sensitive name.
func redactTokens(s string) string {
	var (
		out        strings.Builder
		prog       string
		progKnown  bool
		redactNext bool // the next word is a secret value
		allowAuth  bool // ...unless it is an auth scheme word (after "Authorization:")
		userNext   bool // the next word is user:password
	)
	out.Grow(len(s))
	for len(s) > 0 {
		// Copy leading whitespace verbatim.
		i := 0
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		out.WriteString(s[:i])
		s = s[i:]
		if s == "" {
			break
		}
		j := 0
		for j < len(s) && !isSpace(s[j]) {
			j++
		}
		tok := s[:j]
		s = s[j:]

		if redactNext || userNext {
			wasUser := userNext
			redactNext, userNext = false, false
			switch {
			case looksLikeFlag(tok):
				// No value followed; treat this word normally below.
			case allowAuth && authSchemes[strings.ToLower(tok)]:
				out.WriteString(tok)
				redactNext = true
				allowAuth = false
				continue
			case wasUser:
				out.WriteString(maskUserPass(tok))
				continue
			default:
				out.WriteString(redacted)
				allowAuth = false
				continue
			}
			allowAuth = false
		}

		if !progKnown {
			if !envAssignment.MatchString(tok) && !wrapperProgs[baseName(tok)] {
				prog = baseName(tok)
				progKnown = true
			}
		}

		switch {
		case envAssignment.MatchString(tok):
			m := envAssignment.FindStringSubmatch(tok)
			if sensitiveName(m[1]) {
				tok = m[1] + "=" + redacted
			}
		case flagWithValue.MatchString(tok):
			m := flagWithValue.FindStringSubmatch(tok)
			switch {
			case sensitiveName(m[1]):
				tok = m[1] + "=" + redacted
			case userPassProgs[prog] && m[1] == "--user":
				tok = m[1] + "=" + maskUserPass(m[2])
			}
		case gluedPasswordProgs[prog] && strings.HasPrefix(tok, "-p") && len(tok) > 2:
			tok = "-p" + redacted
		case passwordNextProgs[prog] && tok == "-p":
			redactNext = true
		case userPassProgs[prog] && (tok == "-u" || tok == "--user"):
			userNext = true
		case bareFlag.MatchString(tok):
			if sensitiveName(tok) {
				redactNext = true
			}
		case headerName.MatchString(tok):
			name := headerName.FindStringSubmatch(tok)[1]
			if sensitiveName(name) {
				redactNext = true
				allowAuth = true
			}
		case strings.EqualFold(tok, "bearer"):
			redactNext = true
		}
		out.WriteString(tok)
	}
	return out.String()
}

// maskUserPass turns "user:password" into "user:[REDACTED]". A value with no
// colon may be a bare token, so it is masked whole.
func maskUserPass(v string) string {
	if user, _, ok := strings.Cut(v, ":"); ok {
		return user + ":" + redacted
	}
	return redacted
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}
