# Security notes

This package is a starter pattern, not a complete audited security product.

## Do

- Use passkeys/WebAuthn for account owners.
- Store continuity private keys encrypted or let the customer store them client-side.
- Show recovery codes once and hash them at rest.
- Lock historical account recovery if the domain epoch changes.
- Keep registrar accounts protected with MFA, registrar lock and auto-renew.
- Log epoch changes and alert the old account owner through all available channels.
- Use HSTS, secure cookies, CSRF protection and rate limiting.

## Do not

- Do not treat current DNS/email control as proof of historical identity.
- Do not allow old data recovery from a new domain epoch.
- Do not store private continuity keys in plaintext.
- Do not rely on DNSSEC alone for ownership continuity.
- Do not send password reset links to risky domain addresses without checking epoch continuity.

## Recommended production hardening

- Add WebAuthn/passkey enrollment.
- Add recovery-code table with salted hashes.
- Add background monitoring for MX/NS/DS/DNSKEY changes.
- Add optional Certificate Transparency monitoring for new certificates on protected domains.
- Add registrar/RDAP expiry monitoring where available.
- Add abuse review tooling for high-value domains.
