# Contributing

Thanks for helping improve Domain Continuity Guard.

## Good first contributions

- Improve documentation for hosting providers.
- Add framework adapters for Laravel, Symfony or plain PSR-15 middleware.
- Add PostgreSQL schema support.
- Add WebAuthn/passkey examples.
- Add DNS resolver abstraction and tests.
- Add registrar/RDAP monitoring examples.
- Improve threat-model documentation.

## Development setup

```bash
composer install
composer lint
composer test
```

The current package is a starter implementation. Security-sensitive changes should include a clear explanation of the threat model they affect.

## Pull request checklist

- Keep historical domain ownership separate from current DNS ownership.
- Do not introduce flows where current email access alone can unlock historical accounts.
- Add tests or documented manual verification steps.
- Update docs when changing public methods or database schema.
