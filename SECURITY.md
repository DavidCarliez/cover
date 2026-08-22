# Security Policy

Cover is a security tool. If you find a vulnerability, we want to hear
about it responsibly.

## Supported Versions

Security fixes are applied to the latest release on the `main` branch. There is
no formal LTS policy yet; please use the most recent version.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use Cover's private
[GitHub vulnerability reporting form](https://github.com/DavidCarliez/cover/security/advisories/new)
with:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof of concept if available)
- Affected version or commit hash
- Any suggested fix, if you have one

The maintainers will review the report, work with you to understand the issue,
develop a fix, and coordinate disclosure timing.

## What to Report

Examples of in-scope reports:

- Secrets leaking through the proxy (redaction bypass, incomplete restoration)
- Sensitive data written to disk or logs when it should not be
- Authentication or authorization flaws in the proxy server
- Remote code execution or command injection via config, requests, or model
  download paths
- Denial-of-service issues that could take down the proxy in production use

## Out of Scope

- Issues in third-party dependencies already fixed by their maintainers
- Social engineering attacks
- Missing detections for secret formats not yet covered (file a regular feature
  request instead, unless you can demonstrate a bypass of an existing detector)
- Vulnerabilities in LLM providers Cover proxies to

## Safe Harbor

We support good-faith security research. We will not pursue legal action against
researchers who follow this policy and give us reasonable time to fix issues
before public disclosure.
