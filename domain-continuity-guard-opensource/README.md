# Domain Continuity Guard

**Domain Continuity Guard** is an open source PHP starter project for hosting providers, webmail systems, SaaS platforms, registrars, control panels and identity systems that want to reduce account takeover risk when a domain expires, is sold, is transferred, or is re-registered by a new owner.

The core principle is simple:

> Current DNS or email control proves control of a domain **now**. It does not prove that the person controlling the domain now is the same person who controlled it when an account, mailbox or recovery address was originally created.

This project adds a second layer: a persistent cryptographic domain identity with versioned **domain epochs**. A new owner may be allowed to verify the domain as a new owner, but they must not automatically inherit the old owner's accounts, encrypted data, control-panel access, webmail, password-reset rights or recovery privileges.

---

## The problem this project addresses

Many online accounts use email as the last recovery mechanism. That creates a dangerous edge case for people and companies that use custom domains for side projects, temporary businesses, client work, experiments, newsletters or hosted mail.

Example attack path:

1. Alice owns `example.dk`.
2. Alice creates `alice@example.dk`.
3. Alice uses `alice@example.dk` for SaaS accounts, hosting panels, newsletters, payment services, social accounts or internal tools.
4. Alice later forgets to renew `example.dk`, sells it, abandons it, or loses access through a registrar/payment issue.
5. Bob registers `example.dk` after it becomes available.
6. Bob creates the mailbox `alice@example.dk`.
7. Bob visits a third-party service and clicks **Forgot password**.
8. The third-party service sends a password reset link to `alice@example.dk`.
9. Bob receives the reset email and may be able to take over Alice's old account.

This is not a bug in DNS. It is a weakness in identity assumptions.

Most systems ask only:

> Does this person control the email address or domain today?

For historical account recovery, the safer question is:

> Is this the same domain identity that originally created or controlled the account?

Domain Continuity Guard helps applications answer the second question.

---

## Why DNSSEC alone does not solve this

DNSSEC is valuable, but it does not prove historical ownership continuity.

DNSSEC can prove that a DNS answer is valid for the current DNS zone. It does not prove that the current zone operator is the same person or company as the previous owner.

A new domain owner can usually publish new records such as:

- new `MX` records,
- new `TXT` verification records,
- new DKIM keys,
- new SPF/DMARC policy,
- new DNSSEC keys,
- new DS records through the registrar/registry flow.

That means DNSSEC can say:

> These DNS records are authentic for the domain now.

But DNSSEC cannot safely say:

> This is the same owner who controlled the domain last year.

For that, your application needs a continuity proof that survives DNS changes and cannot be recreated by a later registrant.

---

## What Domain Continuity Guard does

Domain Continuity Guard stores a permanent cryptographic identity for each verified domain.

When a domain is verified for the first time, the application stores:

- the domain name,
- the current epoch number,
- a public continuity key,
- a fingerprint of that key,
- the verification method,
- timestamps and status,
- optional account bindings to that epoch.

Later, if the same domain is verified again, current DNS control is not enough. For sensitive access to historical accounts, the requester must also prove continuity by signing a challenge with the original private continuity key or by passing another strong recovery path such as passkey, recovery code, or manual review.

If DNS verification succeeds but continuity proof fails, the application treats the domain as a possible new owner and creates a new epoch.

Example:

```text
example.dk / epoch 1 = original owner
example.dk / epoch 2 = later registrant or unproven continuity
```

The new epoch may be allowed to create new accounts, new mailboxes and new settings, but it must not unlock data or recovery flows from older epochs.

---

## What this project does not do

This project cannot magically protect accounts on external services that still trust email-only password reset. If a third-party service sends reset links to a recycled custom-domain mailbox without checking continuity, that service remains vulnerable.

This project is intended for systems that can implement safer recovery logic, such as:

- hosting companies,
- webmail providers,
- SaaS products,
- domain registrars,
- control panels,
- customer portals,
- identity providers,
- reseller platforms,
- newsletter platforms,
- developer platforms.

It helps those systems avoid making a dangerous assumption.

---

## Core security model

### Unsafe model

```text
Current email inbox works
=> allow password reset
=> old account may be taken over by new domain owner
```

### Safer model

```text
Current email inbox works
+ domain continuity proof matches stored fingerprint
=> allow sensitive recovery
```

### New-owner model

```text
Current DNS/email control works
+ old continuity proof is missing or invalid
=> create a new domain epoch
=> do not allow access to historical accounts/data
```

---

## Key concepts

### Domain identity key

A long-lived cryptographic key pair associated with the domain at first verification.

- Public key: stored by the application.
- Private key: held by the customer, webmail system, HSM, secure key vault, or client-side encrypted storage.
- Fingerprint: used as the stable identifier for the domain identity.

A future registrant can recreate DNS records, but they cannot recreate the old private key.

### Domain epoch

An epoch represents a specific verified continuity period for a domain.

If continuity is proven, the same epoch can remain active. If continuity cannot be proven after a new DNS verification, the system creates a new epoch.

This lets the same domain name exist across time without treating all owners as the same identity.

### Account binding

Accounts should not be bound only to `user@example.dk`. They should be bound to something like:

```text
email: user@example.dk
domain: example.dk
domain_epoch: 1
domain_identity_fingerprint: sha256:...
```

That way, `user@example.dk` under epoch 2 is not silently treated as the same identity as `user@example.dk` under epoch 1.

---

## Example use cases

### Webmail provider

A webmail provider can prevent a new domain owner from opening mailboxes or encrypted mail archives that belonged to the old owner.

### Hosting control panel

A hosting company can prevent password reset to a control-panel account if the custom-domain email has moved to a new epoch.

### SaaS account recovery

A SaaS platform can block email-only recovery when the recovery email belongs to a domain whose continuity status is uncertain.

### Registrar or reseller portal

A registrar can use continuity checks before allowing access to historical invoices, DNS templates, transfer records or old owner settings.

### Encrypted data systems

A system can refuse to release encrypted backups, keys, exports or account tokens unless the original domain identity is proven.

---

## Typical integration flow

### 1. First domain verification

The application asks the customer to create a DNS TXT record:

```txt
_dcg.example.dk TXT "v=dcg1; token=RANDOM_TOKEN"
```

The application verifies the TXT record and registers the domain with a continuity public key.

Optional public-key publishing:

```txt
_dcg-identity.example.dk TXT "v=dcg1; pubkey=BASE64_PUBLIC_KEY"
```

Important: the DNS record is not the permanent trust anchor. The stored key fingerprint is.

### 2. Account creation or binding

When an account uses an email address on the verified domain, store the current domain epoch with the account.

```text
account_id: 123
email: alice@example.dk
domain: example.dk
domain_epoch: 1
```

### 3. Sensitive recovery request

When someone requests password reset, encrypted mailbox access, control-panel takeover, or security-setting changes, check the bound epoch.

If the request comes from the same domain epoch and other risk checks pass, continue.

If the domain now appears under a different epoch, block email-only recovery.

### 4. Continuity challenge

To prove continuity, the requester signs a server-generated challenge with the original private continuity key.

```text
DCG-CONTINUITY example.dk 2026-05-20T18:00:00Z random_nonce
```

The server verifies the signature against the stored public key.

### 5. New owner handling

If DNS verification passes but the continuity signature fails or is unavailable, create a new epoch and keep old data isolated.

---

## Installation

Requirements:

- PHP 8.1+
- PDO
- MySQL/MariaDB or compatible database
- `ext-sodium`

Clone the repository:

```bash
git clone https://github.com/YOUR-ORG/domain-continuity-guard.git
cd domain-continuity-guard
```

Install dependencies:

```bash
composer install
```

Import the database schema:

```bash
mysql -u root -p dcg < sql/schema.mysql.sql
```

Copy environment example:

```bash
cp .env.example .env
```

Run an example:

```bash
php examples/register-domain.php example.dk
```

---

## Example API usage

```php
use DomainContinuityGuard\DomainContinuityGuard;

$guard = new DomainContinuityGuard($pdo, $_ENV['DCG_APP_SECRET']);

$challenge = $guard->createDnsChallenge('example.dk');

// Ask customer to publish the TXT record.
// Then verify and register the domain identity.
$result = $guard->verifyDnsAndRegisterDomain(
    domain: 'example.dk',
    expectedToken: $challenge['token'],
    publicKeyBase64: $customerPublicKey
);
```

Recovery check:

```php
$result = $guard->canRecoverAccountByEmail($accountId, 'alice@example.dk');

if (!$result['allowed']) {
    // Require passkey, recovery code, continuity signature or manual review.
    throw new RuntimeException($result['reason']);
}
```

---

## Recommended recovery policy

For sensitive actions, do not rely on email alone. Require at least one strong continuity or account-owner proof:

- existing authenticated session plus MFA,
- passkey/WebAuthn,
- recovery code stored hashed at rest,
- valid signature from the stored domain continuity key,
- manual review for high-value accounts.

For high-risk events, notify all available channels:

- old recovery email,
- account owner notification email,
- control-panel alert,
- webhook,
- billing contact,
- security contact,
- registrar contact if available.

---

## Suggested behavior matrix

| Situation | DNS verification | Continuity proof | Recommended action |
|---|---:|---:|---|
| New domain never seen before | Pass | Not required | Create epoch 1 |
| Known domain, same owner proves key | Pass | Pass | Continue same epoch |
| Known domain, key missing | Pass | Fail/missing | Create new epoch; block old data |
| Known account requests password reset, epoch unchanged | N/A | N/A | Allow only with normal risk controls |
| Known account requests password reset, epoch changed | N/A | Fail/missing | Block email-only reset |
| Domain appears transferred or expired | Unknown | Missing | Mark pending reverification |

---

## Repository structure

```text
src/                       Main PHP implementation
sql/                       MySQL schema
examples/                  CLI examples for common flows
.github/                   GitHub issue, PR and CI templates
SECURITY.md                Security policy and hardening notes
CONTRIBUTING.md            Contribution guide
ROADMAP.md                 Suggested future development
composer.json              Composer metadata
```

---

## Security warnings

This is a starter project and reference implementation. It has not been independently audited.

Before production use:

- perform a security review,
- add rate limiting,
- add full audit logging,
- hash recovery codes,
- protect private keys with a KMS/HSM or strong client-side encryption,
- add passkey/WebAuthn support,
- add domain lifecycle monitoring,
- add abuse detection,
- add administrative review tools,
- write integration tests for your recovery flows.

Never store continuity private keys in plaintext.

Never allow a new domain epoch to access old-owner data by default.

Never treat DNSSEC as proof of historical ownership continuity.

---

## Roadmap ideas

- Laravel package wrapper
- Symfony bundle
- WordPress plugin proof of concept
- WHMCS module proof of concept
- cPanel/Plesk integration examples
- WebAuthn/passkey support
- PostgreSQL schema
- SQLite development mode
- DNSSEC-aware resolver integration
- Hosted API mode
- Admin dashboard
- Domain expiry monitoring
- Public specification for domain continuity records

See `ROADMAP.md` for more.

---

## License

MIT. See `LICENSE`.

---

## Project status

Early open source starter. The goal is to make the domain-recycling takeover problem visible and give hosting providers, webmail systems and SaaS platforms a practical pattern they can improve together.
