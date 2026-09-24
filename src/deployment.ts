import { readFileSync } from 'node:fs'
import path from 'node:path'

/**
 * The policy a deployment was built with: the organization's, compiled from
 * the repository it was deployed from, and put beside the service by
 * `fg-dist policy use` during its build. Built from the same commit as the
 * code, so it needs no signature: the repository's history is its record.
 */
export const DEPLOYMENT_BUNDLE = path.join('.policy', 'policies.tar.gz')

export const deploymentBundle = (): Uint8Array | undefined => {
  try {
    // Written out, not built from DEPLOYMENT_BUNDLE, so a build can trace it
    // into the deployment.
    return readFileSync(path.join(process.cwd(), '.policy', 'policies.tar.gz'))
  } catch {
    return undefined
  }
}
