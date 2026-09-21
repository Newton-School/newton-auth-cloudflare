# Releasing

Consumers install this SDK from Git tags:

```bash
npm install github:Newton-School/newton-auth-cloudflare#v0.1.0
```

so every release is a semver Git tag on `main`. `dist/` is not committed; the `prepare` script builds it on install.

## Steps

1. Ensure `main` is green:

   ```bash
   npm test && npm run typecheck && npm run build
   node scripts/wire-compat-check.mjs ../newton-auth-python python3
   node scripts/node-sdk-compat-check.mjs ../newton-auth-nodejs
   ```

2. Bump the version (creates the commit and the `vX.Y.Z` tag):

   ```bash
   npm version patch   # or minor / major
   ```

3. Push the commit and tag:

   ```bash
   git push origin main --follow-tags
   ```

4. Create a GitHub release from the tag with a short changelog.

## Versioning rules

- **patch**: bug fixes, doc updates, internal refactors
- **minor**: new helpers, new config options, backwards-compatible API additions
- **major**: breaking API or wire-format changes (coordinate with newton-api and the Go, Python and Node SDKs before ever doing this)
