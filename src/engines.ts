import { readFile } from 'node:fs/promises'
import { loadPolicy } from '@open-policy-agent/opa-wasm'
import { readBundle } from './bundle.ts'
import { disclose, type Disclosure } from './disclose.ts'
import type { PolicySource } from './types.ts'

export interface Engine {
  /** Which rules answer: the bundle's revision, or where they are asked. */
  revision: string
  evaluate(path: string, input: unknown): Promise<unknown>
  /** Whether the rules decide this, or leave it to the built-in rules. */
  decides(path: string): boolean
  /** The rules, for the people they govern. Absent when they are held elsewhere. */
  disclosure?: Disclosure
}

/** Far more than any policy, gzipped. */
const MAX_DOWNLOAD = 16 * 1024 * 1024

const download = async (url: string, fetcher: typeof fetch): Promise<Uint8Array> => {
  // A policy server that never answers must not hold every decision with it.
  const response = await fetcher(url, { signal: AbortSignal.timeout(10_000) })
  if (!response.ok) throw new Error(`The policy at ${new URL(url).host} answered ${response.status}`)
  if (Number(response.headers.get('content-length') ?? 0) > MAX_DOWNLOAD) {
    throw new Error(`The policy at ${new URL(url).host} is larger than any policy should be.`)
  }
  const bytes = new Uint8Array(await response.arrayBuffer())
  if (bytes.byteLength > MAX_DOWNLOAD) throw new Error(`The policy at ${new URL(url).host} is larger than any policy should be.`)
  return bytes
}

const bundle = async (source: Extract<PolicySource, { engine: 'bundle' }>, fetcher: typeof fetch): Promise<Engine> => {
  const archive =
    typeof source.source !== 'string'
      ? source.source
      : /^https?:\/\//.test(source.source)
        ? await download(source.source, fetcher)
        : await readFile(source.source)
  const read = await readBundle(archive, source)
  const policy = await loadPolicy(read.wasm)
  policy.setData(read.data as object)
  return {
    revision: read.revision,
    disclosure: disclose(read),
    decides: (path) => path in policy.entrypoints,
    async evaluate(path, input) {
      const [first] = policy.evaluate(input, path) as Array<{ result?: unknown }>
      return first?.result
    },
  }
}

const server = (url: string, timeoutMs: number, fetcher: typeof fetch): Engine => {
  const base = url.replace(/\/+$/, '')
  return {
    revision: `server ${base}`,
    // The server holds the rules; asking is the only way to know.
    decides: () => true,
    async evaluate(path, input) {
      const response = await fetcher(`${base}/v1/data/${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ input }),
        signal: AbortSignal.timeout(timeoutMs),
      })
      if (!response.ok) throw new Error(`OPA answered ${response.status}`)
      return ((await response.json()) as { result?: unknown }).result
    },
  }
}

export const loadEngine = (source: PolicySource, timeoutMs: number, fetcher: typeof fetch) =>
  source.engine === 'bundle'
    ? bundle(source, fetcher)
    : Promise.resolve(server(source.url, timeoutMs, fetcher))
