import { spawnSync } from 'node:child_process'
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import type { JWK } from 'jose'
import { readBundle, signFiles, type Bundle } from './bundle.ts'
import { assemble, type Layer } from './layers.ts'
import { opa } from './opa.ts'
import { tar, untar } from './tar.ts'

/**
 * Building an organization's policy: its layers compiled into one bundle,
 * named by what is in it, and signed when there is a key. `fg-policy build`
 * and `fg-dist policy build` both come here.
 */

export interface BuildOptions {
  /** Bases first, the organization's last; from `findLayers`. */
  layers: Array<Layer & { dir: string }>
  /** Where to write the bundle. */
  out: string
  /**
   * The release it belongs to, such as the distribution's version. The
   * revision is this and a digest of the rules and settings, so each change
   * to either is a revision of its own. Defaults to the version in the
   * nearest package.json.
   */
  version?: string
  /** The whole revision, instead. */
  revision?: string
  /** A PEM private key (or PEM in base64): sign it, so it can be checked wherever it goes. */
  signingKey?: string
  keyId?: string
}

/** The version in the nearest package.json: a distribution's is its date. */
export const versionNear = (from: string): string | undefined => {
  for (let dir = from; ; dir = path.dirname(dir)) {
    const file = path.join(dir, 'package.json')
    if (existsSync(file)) {
      const { version } = JSON.parse(readFileSync(file, 'utf8')) as { version?: string }
      if (version) return version
    }
    if (path.dirname(dir) === dir) return undefined
  }
}

/** The commit being built, where one can be found: CI says, or git does. */
const commitOf = (dir: string): string | undefined => {
  const given = process.env.VERCEL_GIT_COMMIT_SHA || process.env.GITHUB_SHA
  if (given) return given
  const git = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' })
  return git.status === 0 ? git.stdout.trim() : undefined
}

/**
 * What the policy says, as a digest: every rule and setting by where it is,
 * and what the organization says about it. Not the versions of what it was
 * built from, nor the commit — the same policy is the same revision.
 */
const digestOf = (assembled: string) => {
  const hash = createHash('sha256')
  const files = readdirSync(assembled, { recursive: true, encoding: 'utf8' })
    .map((file) => file.split(path.sep).join('/'))
    .filter((file) => statSync(path.join(assembled, file)).isFile())
    .sort()
  for (const file of files) {
    const bytes = readFileSync(path.join(assembled, file))
    if (file === '.manifest') {
      const { metadata = {}, ...manifest } = JSON.parse(bytes.toString('utf8')) as { metadata?: Record<string, unknown> }
      const { layers: _layers, commit: _commit, ...said } = metadata
      hash.update(`${file}\0${JSON.stringify({ ...manifest, metadata: said })}\0`)
    } else {
      hash.update(`${file}\0`).update(bytes).update('\0')
    }
  }
  return hash.digest('hex').slice(0, 12)
}

/** PEM, or PEM in base64 — what fits in a secret. */
const pem = (text: string) => (text.trim().startsWith('-----BEGIN') ? text : Buffer.from(text, 'base64').toString('utf8'))

export const buildBundle = async (options: BuildOptions): Promise<{ bundle: Bundle; archive: Uint8Array }> => {
  const organization = options.layers.at(-1)!
  const scratch = mkdtempSync(path.join(tmpdir(), 'fg-policy-'))
  let files: Map<string, Uint8Array>
  try {
    const assembled = path.join(scratch, 'policies')
    const sources = assemble(options.layers, assembled, { commit: commitOf(organization.dir) })
    const version = options.version ?? versionNear(organization.dir)
    const revision = options.revision ?? `${version ? `${version}+` : ''}${digestOf(assembled)}`

    const compiled = path.join(scratch, 'bundle.tar.gz')
    await opa(['build', '--bundle', '-t', 'wasm', '-o', compiled, '--revision', revision, '.'], assembled)
    files = new Map(untar(readFileSync(compiled)))
    for (const { name, from } of sources) files.set(name, readFileSync(from))
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }

  const privateKey = options.signingKey ? createPrivateKey(pem(options.signingKey)) : undefined
  if (privateKey) files = await signFiles(files, privateKey, options.keyId)
  const archive = tar(files)
  mkdirSync(path.dirname(options.out), { recursive: true })
  // Whole or not at all: a service copying it meanwhile never gets half.
  const partial = `${options.out}.${process.pid}.partial`
  writeFileSync(partial, archive)
  renameSync(partial, options.out)

  const publicKey = privateKey && (createPublicKey(privateKey).export({ format: 'jwk' }) as JWK)
  return { bundle: await readBundle(archive, publicKey ? { publicKey } : { allowUnsigned: true }), archive }
}

/**
 * Each base's tests on its own rules; each parent's on the layers beneath it;
 * then the organization's on all of them.
 */
export const testLayers = async (layers: Array<Layer & { dir: string }>, log: (line: string) => void = console.log) => {
  for (const layer of layers.filter((candidate) => candidate.role === 'base')) {
    log(`\n${layer.path}, on its own:`)
    await opa(['test', layer.dir, '-v'])
  }
  const bases = layers.filter((layer) => layer.role === 'base')
  const stacks = layers
    .map((layer, index) => ({ layer, beneath: layers.slice(0, index + 1) }))
    .filter(({ layer }) => layer.role !== 'base')
  for (const { layer, beneath } of stacks) {
    const scratch = mkdtempSync(path.join(tmpdir(), 'fg-policy-'))
    try {
      assemble(beneath, scratch, { tests: true })
      if (beneath.length > 1) log(`\n${layer.path}, on top of ${beneath.length - 1 === bases.length ? 'them' : 'the layers beneath it'}:`)
      await opa(['test', scratch, '-v'])
    } finally {
      rmSync(scratch, { recursive: true, force: true })
    }
  }
}

export { findLayers, type Layer } from './layers.ts'
export { findOpa, OPA_VERSION, OpaFailed } from './opa.ts'
