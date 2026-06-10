# Agent Guidance

This file applies to the whole `micronaut-security` repository. Keep changes
focused on Micronaut Security behavior, tests, and documentation; do not fold in
unrelated company, workflow, or template-package policy.

## Repository Shape

- Confirm the intended target branch before opening a pull request. Use the
  repository default branch and current release line unless the issue or
  maintainer guidance names a different target.
- The root project coordinates the build and documentation. Key published
  modules include `security-bom`, `security`, `security-annotations`,
  `security-aot`, `security-csrf`, `security-jwt`, `security-ldap`,
  `security-oauth2`, `security-processor`, and `security-session`.
- `test-suite*` projects provide cross-module and integration coverage,
  including AOT, GraalVM, JWT, JWKS, Keycloak, LDAP, servlet, and serialization
  scenarios. Prefer the closest suite before broadening to full repository
  checks.
- User guide sources live in `src/main/docs/guide`. Update `toc.yml` when adding
  or moving guide pages.
- Some root files and GitHub workflows are synchronized from the Micronaut
  project template. Avoid local edits to synchronized files unless the task
  explicitly requires a repo-specific override.

## Code Conventions

- Follow nearby Micronaut patterns before introducing new abstractions.
- Use `jakarta.inject` APIs, constructor injection where practical, and existing
  Micronaut configuration patterns for configuration models.
- Use existing JSpecify annotations from `org.jspecify.annotations` for new or
  changed nullability contracts.
- Mark non-user-facing APIs with `@Internal`. Mark unstable user-facing APIs
  with `@Experimental`.
- Preserve binary compatibility for public APIs. Prefer adding overloads or
  deprecating with replacement guidance over changing existing signatures.
- Use the Gradle version catalogs for dependencies; do not hard-code dependency
  versions in module build files.

## Security-Specific Notes

- Authentication, authorization, token parsing, CSRF, session, OAuth 2.0, OIDC,
  JWT, JWKS, cookie, and header behavior is security-sensitive. Changes there
  need focused tests for both accepted and rejected paths.
- Keep secret material, tokens, keys, and credentials out of examples, logs, and
  tests unless they are explicit non-secret fixtures.
- When changing token validation, claim generation, key resolution, or
  `WWW-Authenticate` behavior, consider interoperability with OAuth 2.0/OIDC
  clients and update docs if externally visible behavior changes.
- GraalVM and AOT behavior matters for security modules. If a change affects
  reflection, resources, service loading, annotations, or generated metadata,
  run the relevant `test-suite-aot*` or `test-suite-graal` coverage.

## Verification

Use the narrowest Gradle task that proves the change, then expand if shared
behavior or public API is affected. Common examples:

```bash
./gradlew :security:test
./gradlew :security-jwt:test
./gradlew :security-oauth2:test
./gradlew :test-suite:test
./gradlew :test-suite-jwks-cache:test
./gradlew docs
./gradlew check
```

For docs-only or instruction-only changes, record the targeted validation you
performed; a full Gradle build is not automatically required.
