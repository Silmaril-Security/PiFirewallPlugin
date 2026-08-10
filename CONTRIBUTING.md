# Contributing

Use a branch from current `origin/main`. Keep Pi-native behavior, fail-open defaults, exact `MALICIOUS` enforcement, extension-input recursion prevention, and raw-content non-retention intact.

Before submitting a change, run:

```sh
npm ci
npm run lint
npm test
npm run pack:dry
```

Do not add secrets, customer payloads, raw lifecycle fixtures, generated credentials, or production endpoints.
