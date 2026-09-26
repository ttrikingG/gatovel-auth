# Gatovel Auth Documentation

Welcome to the Gatovel Auth documentation.

Gatovel Auth is a modular authentication and authorization package for PHP applications built with the Gatovel Framework.

## Documentation

### Getting Started

* [Installation](installation.md)
  Installation and basic package configuration.

### Authentication

* [Authentication](authentication.md)
  User authentication, login, logout, sessions and authentication providers.

* [Authorization](authorization.md)
  Authorization concepts, contracts and integration with application-level permissions.

### Security

* [Multi-Factor Authentication](mfa.md)
  MFA and TOTP configuration and authentication flow.

* [CSRF Protection](csrf.md)
  Cross-Site Request Forgery protection and usage.

### OAuth

* [OAuth](oauth.md)
  OAuth authentication and provider integration.

### Account Management

* [Email Verification](email-verification.md)
  Email verification and verification tokens.

* [Password Recovery](password-recovery.md)
  Password recovery, reset tokens and password changes.

### Architecture

* [Architecture](architecture.md)
  Package architecture, contracts, providers and application integration.

## Package Structure

```text
gatovel-auth/
├── composer.json
├── LICENSE
├── README.md
├── docs/
│   ├── README.md
│   ├── installation.md
│   ├── authentication.md
│   ├── authorization.md
│   ├── mfa.md
│   ├── oauth.md
│   ├── password-recovery.md
│   ├── email-verification.md
│   ├── csrf.md
│   └── architecture.md
└── src/
    └── auth/
```

## Project

Gatovel Auth is part of the Gatovel ecosystem and is developed as an independent Composer package.

Repository:

[GitHub](https://github.com/ttrikingG/gatovel-auth)

## License

Gatovel Auth is released under the [MIT License](../LICENSE).
