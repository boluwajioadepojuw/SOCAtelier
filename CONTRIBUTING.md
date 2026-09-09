# Contributing

Thanks for your interest in this project.

## Support posture

The project is published as-is. Pull requests are welcome. Issues are read,
but response time is best-effort, not an SLA.

## What makes a good pull request

- **Bug fixes** come with a test in the style of the existing suite.
- **Features** are scoped, documented, and add no unnecessary runtime
  dependencies.
- **Safe-direction rule**: changes that touch detection or response logic
  must err toward more visibility and safety, never silently toward less.
  Changes that trade correctness for tidiness will be declined.

## Development workflow

1. Fork the repository and create a feature branch.
2. Make your change with tests.
3. Run the test suite locally.
4. Open a pull request describing the change and the evidence.

## What will be declined

- Changes that commit real secrets, real customer data, or anything that
  identifies a specific organization.
- New runtime dependencies without strong justification.
- Renames or reformats that mix unrelated changes into a single PR.

## Licensing

By contributing, you agree that your contributions are licensed under the
same license as this project (see `LICENSE`).
