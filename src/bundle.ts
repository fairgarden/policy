import { createHash, createPublicKey, type KeyObject } from 'node:crypto'
import { calculateJwkThumbprint, CompactSign, compactVerify, decodeJwt, decodeProtectedHeader, importJWK, importSPKI, type JWK } from 'jose'
import { untar } from './tar.ts'
import type { PublicKeys } from './types.ts'

/**
 * An OPA bundle, as `fg-policy build` writes it: the compiled module,
 * `data.json`, a `.manifest` with the revision, the Rego as it was written,
 * and — when signed — `.signatures.json`.
 *
 * Signatures are made and checked the way OPA makes and checks them, so a
 * bundle signed here is trusted by an OPA server, and one OPA signed is
 * trusted here.
 */

export interface Annotations {
  title?: string
  description?: string
  [key: string]: unknown
}

export interface Manifest {
  revision?: string
  roots?: string[]
  wasm?: Array<{ entrypoint: string; module: string; annotations?: Annotations[] }>
  /** Whatever the organization says about itself: a name, where the policy is kept. */
  metadata?: Record<string, unknown>
}

export interface Bundle {
  /** Every file, by name. */
  files: Map<string, Uint8Array>
  manifest: Manifest
  /** `data.json`: settings the organization's rules read. */
  data: unknown
  /** The compiled module. */
  wasm: Uint8Array
  /** Who signed it, when someone did. */
  signature?: { keyId: string; algorithm: string }
  /** The manifest's revision, or a hash of the bundle without one. */
  revision: string
}

export interface BundleTrust {
  /**
   * The organization's public key, as PEM or a JWK, or a JWK Set while one
   * key is replacing another — as text, base64, or parsed. A signed bundle is
   * checked against it.
   */
  publicKey?: PublicKeys
  /** Accept a bundle nobody signed. Only for writing policy locally. */
  allowUnsigned?: boolean
}

export class BundleRejectedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BundleRejectedError'
  }
}

const SIGNATURES = '.signatures.json'

/**
 * Where the Rego is kept as written. Compiling to WebAssembly rewrites the
 * compiled rules out of a bundle's `.rego` files; OPA ignores these.
 */
export const sourcePath = (rego: string) => `sources/${rego}.txt`
export const isSourcePath = (name: string) => name.startsWith('sources/') && name.endsWith('.rego.txt')

/**
 * OPA hashes JSON by its value — keys sorted, nothing escaped, and numbers as
 * written, so `1.0` stays `1.0` — and anything else by its bytes.
 */
const rawJSON = (JSON as unknown as { rawJSON(text: string): unknown; isRawJSON(value: unknown): boolean })

const canonical = (value: unknown): unknown =>
  Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === 'object' && !rawJSON.isRawJSON(value)
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((key) => [key, canonical((value as Record<string, unknown>)[key])])
        )
      : value

/** JSON, with each number kept as the text it was written as. */
const parseKeepingNumbers = (text: string): unknown =>
  (JSON.parse as (text: string, reviver: (key: string, value: unknown, context: { source: string }) => unknown) => unknown)(
    text,
    (_key, value, context) => (typeof value === 'number' ? rawJSON.rawJSON(context.source) : value)
  )

export const hashFile = (name: string, bytes: Uint8Array): string => {
  const hash = createHash('sha256')
  if (name.endsWith('.json') || name === '.manifest') {
    hash.update(JSON.stringify(canonical(parseKeepingNumbers(Buffer.from(bytes).toString('utf8')))))
  } else {
    hash.update(bytes)
  }
  return hash.digest('hex')
}

const decodeKeys = (keys: PublicKeys, encoded = false): Array<string | JWK> => {
  if (typeof keys !== 'string') return 'keys' in keys && Array.isArray(keys.keys) ? keys.keys : [keys as JWK]
  const text = keys.trim()
  if (text.startsWith('-----BEGIN')) return [text]
  if (text.startsWith('{')) return decodeKeys(JSON.parse(text) as PublicKeys, true)
  // Base64 once, for what fits in an environment variable; not twice.
  if (!encoded && text) return decodeKeys(Buffer.from(text, 'base64').toString('utf8'), true)
  throw new Error('The public key is not PEM, a JWK or a JWK Set, nor any of them in base64.')
}

/**
 * A key's id, when nobody named it: its RFC 7638 thumbprint, so `fg-policy
 * build` and `fg-policy keygen` agree on it without being told.
 */
export const keyIdOf = async (key: string | JWK): Promise<string> =>
  typeof key === 'string'
    ? calculateJwkThumbprint(createPublicKey(key).export({ format: 'jwk' }) as JWK)
    : (key.kid ?? calculateJwkThumbprint(key))

const importKey = (key: string | JWK, algorithm: string) =>
  typeof key === 'string' ? importSPKI(key, algorithm) : importJWK(key, algorithm)

/** The keys a signature could be from: the one it names first, then the rest. */
const candidates = async (keys: PublicKeys, keyId: string | undefined) => {
  const decoded = decodeKeys(keys)
  const ids = await Promise.all(decoded.map((key) => keyIdOf(key).catch(() => undefined)))
  const named = decoded.filter((_, index) => keyId !== undefined && ids[index] === keyId)
  return [...named, ...decoded.filter((key) => !named.includes(key))]
}

/** The JWS algorithm for a private key, as OPA names it. */
export const algorithmOf = (key: KeyObject): string => {
  const curve = key.asymmetricKeyDetails?.namedCurve
  if (key.asymmetricKeyType === 'rsa') return 'RS256'
  if (key.asymmetricKeyType === 'ec' && curve === 'prime256v1') return 'ES256'
  if (key.asymmetricKeyType === 'ec' && curve === 'secp384r1') return 'ES384'
  if (key.asymmetricKeyType === 'ec' && curve === 'secp521r1') return 'ES512'
  throw new Error(`OPA cannot check a signature from a ${key.asymmetricKeyType} ${curve ?? ''} key: use RSA or ECDSA.`)
}

/** Sign every file, as `opa build --signing-key` does. */
export const signFiles = async (
  files: Map<string, Uint8Array>,
  privateKey: KeyObject,
  keyId?: string
): Promise<Map<string, Uint8Array>> => {
  const signed = new Map(files)
  signed.delete(SIGNATURES)
  const payload: SignedFiles = {
    files: [...signed].map(([name, bytes]) => ({ name, hash: hashFile(name, bytes), algorithm: 'SHA-256' })),
    keyid: keyId ?? (await keyIdOf(createPublicKey(privateKey).export({ format: 'jwk' }) as JWK)),
  }
  const token = await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: algorithmOf(privateKey), typ: 'JWT' })
    .sign(privateKey)
  signed.set(SIGNATURES, Buffer.from(JSON.stringify({ signatures: [token] })))
  return signed
}

interface SignedFiles {
  files: Array<{ name: string; hash: string; algorithm: string }>
  keyid?: string
}

const verify = async (files: Map<string, Uint8Array>, publicKey: PublicKeys) => {
  const { signatures } = JSON.parse(Buffer.from(files.get(SIGNATURES)!).toString('utf8')) as {
    signatures?: string[]
  }
  const [token] = signatures ?? []
  if (!token) throw new BundleRejectedError('The bundle has an empty signature file.')

  const { alg = 'RS256', kid } = decodeProtectedHeader(token)
  // Only to pick which key to try first; nothing is believed until it verifies.
  const named = kid ?? (decodeJwt(token) as { keyid?: string }).keyid
  let payload: SignedFiles | undefined
  for (const key of await candidates(publicKey, named)) {
    try {
      const verified = await compactVerify(token, await importKey(key, alg))
      payload = JSON.parse(new TextDecoder().decode(verified.payload)) as SignedFiles
      break
    } catch {
      // Not this key; perhaps the next.
    }
  }
  if (!payload) throw new BundleRejectedError("The bundle's signature is not the organization's.")

  // Every file signed for is there and unchanged, and nothing else is.
  const signed = new Map(payload.files.map((file) => [file.name.replace(/^\//, ''), file]))
  for (const [name, bytes] of files) {
    if (name === SIGNATURES) continue
    const entry = signed.get(name)
    if (!entry) throw new BundleRejectedError(`${name} is in the bundle but was not signed.`)
    if (entry.algorithm.toUpperCase() !== 'SHA-256') {
      throw new BundleRejectedError(`${name} is signed with ${entry.algorithm}, which is not supported.`)
    }
    if (entry.hash !== hashFile(name, bytes)) throw new BundleRejectedError(`${name} was changed after it was signed.`)
    signed.delete(name)
  }
  if (signed.size > 0) {
    throw new BundleRejectedError(`${[...signed.keys()].join(', ')} was signed but is missing.`)
  }
  return { keyId: payload.keyid ?? kid ?? 'default', algorithm: alg }
}

const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

/** Every `data.json`, at the path of its directory, as OPA reads a bundle's data. */
const dataOf = (files: Map<string, Uint8Array>): Record<string, unknown> => {
  const data: Record<string, unknown> = {}
  const merge = (target: Record<string, unknown>, value: unknown) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return
    for (const [key, inner] of Object.entries(value)) {
      // Settings are data, never this process's prototypes.
      if (UNSAFE_KEYS.has(key)) continue
      const existing = target[key]
      if (existing && typeof existing === 'object' && !Array.isArray(existing) && inner && typeof inner === 'object') {
        merge(existing as Record<string, unknown>, inner)
      } else {
        target[key] = inner
      }
    }
  }
  for (const [name, bytes] of files) {
    if (name !== 'data.json' && !name.endsWith('/data.json')) continue
    const value = JSON.parse(Buffer.from(bytes).toString('utf8'))
    const at = name.split('/').slice(0, -1).reduceRight<unknown>((inner, key) => ({ [key]: inner }), value)
    merge(data, at)
  }
  return data
}

/** Read a bundle, refusing one whose signature does not hold. */
export const readBundle = async (archive: Uint8Array, trust: BundleTrust = {}): Promise<Bundle> => {
  const files = untar(archive)
  let signature: Bundle['signature']
  if (files.has(SIGNATURES)) {
    if (trust.publicKey) signature = await verify(files, trust.publicKey)
    else if (!trust.allowUnsigned) {
      throw new BundleRejectedError('The bundle is signed, but no public key is configured to check it.')
    }
  } else if (!trust.allowUnsigned) {
    throw new BundleRejectedError('The bundle is not signed.')
  }

  const text = (name: string) => {
    const bytes = files.get(name)
    return bytes ? Buffer.from(bytes).toString('utf8') : undefined
  }
  const manifest = JSON.parse(text('.manifest') ?? '{}') as Manifest
  const module = (manifest.wasm?.[0]?.module ?? 'policy.wasm').replace(/^\//, '')
  const wasm = files.get(module)
  if (!wasm) throw new BundleRejectedError('The bundle has no compiled policy: build it with -t wasm.')

  return {
    files,
    manifest,
    data: dataOf(files),
    wasm,
    signature,
    revision: manifest.revision || createHash('sha256').update(archive).digest('hex').slice(0, 16),
  }
}
