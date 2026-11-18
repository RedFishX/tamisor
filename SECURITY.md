# Security

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private reporting: the **Security** tab of the repository, then
**Report a vulnerability**. A first response is given within 7 days.

## Threat model

- The web application analyses files **in the browser** (Web Worker). The Docker container only serves static
  files and rejects request bodies; no configuration is sent to a server.
- Preferences, acknowledgements and the meeting board are stored in the browser's `localStorage`; the history
  only contains counters (IndexedDB), never the content of the configuration.
- FortiGate exports often contain sensitive data: never attach a real, non-anonymised configuration to an issue.
