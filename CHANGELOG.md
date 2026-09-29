# Changelog

## [0.1.2] - Unreleased

### Security

- Redact secrets (API keys, tokens, passwords, credentials in URLs and
  headers, well-known token formats) from process command lines on the
  server, before truncation, on every platform.
- Add the `show_commands` operator setting (default on); when off, no
  command lines are sent to the UI.
