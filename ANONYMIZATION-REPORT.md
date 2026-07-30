# Anonymization report

Status: release content scanned again after component history repair on
2026-09-16; `gitleaks` was not available locally.

The export excludes private keys, credentials, cluster inventories, raw
deployment logs, generated signing material, and external symlinks. The only
email matches are synthetic test fixtures (`example.com` / `attacker.com`), not
personal contact data. The final deterministic scan covers 213 files: the
required private provenance marker count is 0, non-loopback IPs, key material,
external symlinks, nested Git directories, and credential values are 0, and 8
generic local temporary code paths are classified as local runtime defaults.
`gitleaks` was unavailable locally. Machine-readable findings are in
`anonymization-findings.json`; unresolved high-risk findings: 0.

The component repositories retain unmodified public upstream author identities and
history. Their added commits use the anonymous artifact identity. Scans of both
integration patches found no private provenance, infrastructure identifiers,
non-loopback IPs, private keys, or credential values. Private development commit
objects were not imported. Upstream license and NOTICE files were checked for
byte equality against the public bases; public upstream examples and historical
attribution are not anonymized.
