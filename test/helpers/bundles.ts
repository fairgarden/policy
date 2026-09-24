import { execFileSync, spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import type { JWK } from 'jose'

// Built with the CLI, which needs the opa CLI; tests skip where there is none.
const opa = process.env.OPA ?? 'opa'
export const hasOpa = spawnSync(opa, ['version']).status === 0

const cli = path.resolve(import.meta.dirname, '../../src/cli.ts')
/** A service's rules in `base/`, and an organization's on top in `policies/`. */
export const fixtures = path.resolve(import.meta.dirname, '../fixtures')

export const keyPair = (type: 'ec' | 'rsa' = 'ec') => {
  const { privateKey, publicKey } =
    type === 'ec' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : generateKeyPairSync('rsa', { modulusLength: 2048 })
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    publicJwk: publicKey.export({ format: 'jwk' }) as JWK,
  }
}

/**
 * The fixture policy, built into a bundle: signed with `privatePem`, or not;
 * as revision 2026.10.01, unless `revision` is false.
 */
export const buildBundle = (
  privatePem?: string,
  { revision = '2026.10.01' as string | false, cwd = fixtures, env = {} as Record<string, string> } = {}
): Uint8Array => {
  const dir = mkdtempSync(path.join(tmpdir(), 'fg-policy-test-'))
  const out = path.join(dir, 'policies.tar.gz')
  const args = [cli, 'build', '--base', 'base', '--out', out, ...(revision ? ['--revision', revision] : [])]
  if (privatePem) {
    writeFileSync(path.join(dir, 'key.pem'), privatePem, { mode: 0o600 })
    args.push('--signing-key', path.join(dir, 'key.pem'))
  }
  execFileSync(process.execPath, args, { cwd, env: { ...process.env, OPA: opa, ...env }, stdio: 'ignore' })
  return readFileSync(out)
}

export { tar } from '../../src/tar.ts'
