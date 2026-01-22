# Project Context

## Purpose
Go library for handling OpenID Connect flows and JWT validation/processing, shared across Plan42 services.

## Tech Stack
- Go 1.25
- Standard library crypto/jwt handling with minimal dependencies
- Test utilities via testify

## Project Conventions

### Code Style
Use gofmt formatting and golangci-lint via `make lint`. Follow idiomatic naming for tokens/claims and keep public APIs small and well-documented.

### Architecture Patterns
Package exposes client and JWT helpers under `internal` and `jwt` directories. Emphasizes clear separation between token fetching, verification, and claim parsing.

### Testing Strategy
`go test ./...` exercises token parsing, verification, and client logic. Keep tests deterministic with fixed keys/fixtures and avoid external network calls.

### Git Workflow
Feature branches with PR review. Tag releases with `make tag` when publishing updates for downstream services.

## Domain Context
Library is consumed by services implementing OpenID/OAuth-style auth flows. Correct validation (issuer/audience, signing keys) is critical; breaking changes can impact authentication across the platform.

## Important Constraints
- Handle keys and tokens securely; avoid logging sensitive fields.
- Maintain backward compatibility for token parsing helpers to prevent auth outages.
- Keep dependencies light to reduce attack surface.

## External Dependencies
- OpenID providers for JWKS discovery and token issuance (configured by consumers)
