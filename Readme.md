# FairGarden Policy

<!-- fg:version -->

Version **0.1.0-alpha.0**

<!-- /fg:version -->

<!-- fg:releasing -->

## Releasing

This module releases on its own. `0.1.0-alpha.0` is what main is working towards,
not what is published — the version here is always the next one.

1. **Publish it.** Run the *Publish* workflow from the Actions tab, picking the
   dist tag. It refuses if that version is already on npm.
2. **Move it on.** `pnpm release` — opens a pull request bumping this branch
   to `0.1.0-alpha.1`, or `pnpm release --id rc` to change
   identifier. A prerelease gets no maintenance branch; there is no released
   line behind it yet.

Every push to main publishes `@fairgarden/policy@canary`. A canary is not a release and
carries no promise; it is there so main can be tried without a checkout.

<!-- /fg:releasing -->

A community organization's policy for the services it runs, as
[Open Policy Agent](https://www.openpolicyagent.org) Rego: written and kept by
the organization, shown in full to the people it governs, run inside each
service, and every decision recorded.

```ts
import { createPolicy, policySourceFromEnv } from '@fairgarden/policy'
import { decisionLogTable, drizzleLogger, drizzleRevisions, revisionTable } from '@fairgarden/policy/drizzle'

export const policyDecisions = decisionLogTable('members_policy_decisions')
export const policyRevisions = revisionTable('members_policy_revisions')

const policy = createPolicy<{
  admit: { input: AdmitInput; result: { allow: boolean; status: string; reasons: Record<string, string> } }
}>({
  package: 'fairgarden/members',
  source: policySourceFromEnv(),
  builtIn: { admit: () => ({ allow: true, status: 'active', reasons: {} }) },
  loggers: [drizzleLogger(db, policyDecisions)],
  onRevision: drizzleRevisions(db, policyRevisions).record,
})

const { allow, reasons } = await policy.decide('admit', input)
```

- **In layers.** Each service ships its questions and places for an
  organization's rules; the organization's `policies/` fills them in — its
  bylaws on who may join, say. Upgrading a service keeps them.
- **From the repository.** A distribution builds its policy once, with turbo,
  when it is deployed, and each service runs its copy in process. Nothing to
  publish; `fg-dist policy` does the finding.
- **Disclosed.** Every decision is described in the organization's words, and
  every rule can be read, along with where it came from.
- **Recorded.** Every decision is logged in OPA's own format, labelled with the
  policy revision that made it, and every revision is kept.
- **Closed when broken.** A decision that cannot be made is no.
- **Signed, when it leaves.** A bundle from outside the repository runs only
  when it is signed by the organization's key.

## Documentation

```bash
pnpm --filter @fairgarden/policy-docs dev   # http://localhost:3036
```

- **Overview**, **Layers** and **Bylaws as policy** — who writes what, and examples
- **Decisions**, **Rego** — writing them
- **Deploying** — built from the repository, once; signed when it leaves
- **The decision log** — every decision, and the revision that made it
- **Commands** and **Functions** — `fg-policy` and the API

## Install

```bash
pnpm add @fairgarden/policy
```

| Import | For |
| --- | --- |
| `@fairgarden/policy` | `createPolicy`, bundles, disclosure, the loggers and the types |
| `@fairgarden/policy/drizzle` | decision log and revision tables, for Drizzle over Postgres |
| `@fairgarden/policy/build` | building and testing layers, for tools |

It also installs `fg-policy`, which builds and tests policy with the
[opa CLI](https://www.openpolicyagent.org/docs/#1-download-opa), fetching a
pinned release when there is none:

```bash
fg-policy build --base 'apps/*/policies'   # policies/, on every service's own
fg-policy test --base 'apps/*/policies'
fg-policy keygen                           # for a bundle that leaves the repository
fg-policy inspect policies.tar.gz
```
