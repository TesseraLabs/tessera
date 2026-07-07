# Contributing to Tessera

Thank you for considering a contribution!

## Contributor License Agreement (CLA)

Before your first pull request can be merged, you must sign our
[Individual CLA](docs/cla/CLA-individual.md). The process is automated:

1. Open your pull request.
2. The CLA bot posts a comment with instructions.
3. Reply with the signing comment, adding your full name on the next line:

   ```
   I have read the CLA Document and I hereby sign the CLA
   Full name: Ivan Petrov
   ```

4. The CLA check turns green. You only sign once — future PRs pass
   automatically.

**Contributing as an employee?** If the code you contribute belongs to your
employer (work made for hire / служебное произведение), your individual
signature is not sufficient. Ask your employer to execute the
[Corporate CLA](docs/cla/CLA-corporate.md) — send the signed document to
**certauth@robonet.me**.

The CLA document may be updated from time to time; if it is, the bot will ask
you to re-sign the new version on your next pull request.

## Development

See [docs/ru/development.md](docs/ru/development.md) for build instructions, test
setup, and coding conventions.

## Pull requests

- Target the `main` branch.
- Run `cargo fmt`, `cargo clippy` and `cargo test` before submitting.
- Keep PRs focused: one logical change per PR.
