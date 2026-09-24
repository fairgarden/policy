import { deploymentBundle } from './deployment.ts'
import type { PolicySource } from './types.ts'

/**
 * The organization's policy, for a service to run:
 *
 * - The one its deployment was built with (`.policy/policies.tar.gz`, which
 *   `fg-dist policy use` puts there), unless one of these says otherwise.
 * - `FG_POLICY_BUNDLE` — a bundle from elsewhere, as a path or an https URL,
 *   which must be signed; or `none`, for the built-in rules whatever the
 *   deployment was built with.
 * - `FG_POLICY_PUBLIC_KEY` — the organization's public key: PEM, a JWK, or a
 *   JWK Set while one key replaces another; as text or base64. Required
 *   with `FG_POLICY_BUNDLE`, and checked against the deployment's own
 *   bundle too when that is signed.
 * - `FG_POLICY_ALLOW_UNSIGNED` — `true` to run an unsigned `FG_POLICY_BUNDLE`,
 *   for writing policy locally.
 * - `FG_POLICY_OPA_URL` — an OPA server to ask instead, which loads and
 *   checks the bundle itself.
 *
 * With none of them, and no bundle from the deployment, the service's
 * built-in rules decide.
 */
export const policySourceFromEnv = (env: Record<string, string | undefined> = process.env): PolicySource | undefined => {
  const setting = (name: string) => env[name]?.trim() || undefined
  const bundle = setting('FG_POLICY_BUNDLE')
  const url = setting('FG_POLICY_OPA_URL')
  if (bundle && url) throw new Error('Set FG_POLICY_BUNDLE or FG_POLICY_OPA_URL, not both.')
  if (url) return { engine: 'server', url }
  if (bundle === 'none') return undefined
  const publicKey = setting('FG_POLICY_PUBLIC_KEY')
  if (!bundle) {
    const built = deploymentBundle()
    return built ? { engine: 'bundle', source: built, allowUnsigned: true, ...(publicKey ? { publicKey } : {}) } : undefined
  }

  const allowUnsigned = setting('FG_POLICY_ALLOW_UNSIGNED') === 'true'
  if (!publicKey && !allowUnsigned) {
    throw new Error(
      "FG_POLICY_BUNDLE is set without FG_POLICY_PUBLIC_KEY. Set it to the organization's public key, " +
        'so that only policy the organization signed is run (or FG_POLICY_ALLOW_UNSIGNED=true, locally).'
    )
  }
  return { engine: 'bundle', source: bundle, ...(publicKey ? { publicKey } : {}), ...(allowUnsigned ? { allowUnsigned } : {}) }
}
