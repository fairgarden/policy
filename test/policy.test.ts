import { mkdtempSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import {
  createPolicy,
  erase,
  jsonLinesLogger,
  policySourceFromEnv,
  PolicyUnavailableError,
  type DecisionLogEntry,
  type PolicySource,
} from '../src/index.ts'
import { buildBundle, hasOpa, keyPair } from './helpers/bundles.ts'

type Example = {
  authz: { input: { user: string }; result: { allow: boolean } }
  release: { input: { scopes: string[] }; result: { scopes: string[]; reasons?: Record<string, string> } }
  /** Not in the fixture policy, so always the built-in rule. */
  greet: { input: { name: string }; result: { greeting: string } }
}

const builtIn = {
  authz: ({ user }: { user: string }) => ({ allow: user === 'alice' }),
  release: ({ scopes }: { scopes: string[] }) => ({ scopes }),
  greet: ({ name }: { name: string }) => ({ greeting: `Hello, ${name}` }),
}

const example = (source?: PolicySource, extra: Partial<Parameters<typeof createPolicy<Example>>[0]> = {}) => {
  const log: DecisionLogEntry[] = []
  const policy = createPolicy<Example>({
    package: 'example.policy',
    source,
    builtIn,
    loggers: [(entry) => void log.push(entry)],
    labels: { service: 'test' },
    ...extra,
  })
  return { policy, log }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('the built-in rules', () => {
  it('answer, and every answer is logged as OPA logs its own', async () => {
    const { policy, log } = example()
    expect(policy.engine).toBe('builtin')
    expect(await policy.disclose()).toBeUndefined()
    expect(await policy.decide('authz', { user: 'alice' })).toEqual({ allow: true })
    expect(await policy.decide('authz', { user: 'mallory' })).toEqual({ allow: false })

    expect(log).toHaveLength(2)
    expect(log[1]).toEqual({
      decision_id: expect.stringMatching(/^[0-9a-f-]{36}$/),
      path: 'example/policy/authz',
      input: { user: 'mallory' },
      result: { allow: false },
      timestamp: expect.stringMatching(/^\d{4}-\d\d-\d\dT/),
      labels: { service: 'test', engine: 'builtin', revision: 'builtin' },
      metrics: { timer_rego_query_eval_ns: expect.any(Number) },
    })
    expect(log[0].decision_id).not.toBe(log[1].decision_id)
  })

  it('fail closed, and the failure is logged', async () => {
    const { policy, log } = example(undefined, {
      builtIn: { ...builtIn, authz: () => { throw new Error('broken rule') } },
    })
    await expect(policy.decide('authz', { user: 'alice' })).rejects.toBeInstanceOf(PolicyUnavailableError)
    expect(log[0]).toMatchObject({ path: 'example/policy/authz', error: 'broken rule' })
    expect(log[0]).not.toHaveProperty('result')
  })
})

describe('the decision log', () => {
  it('leaves out what it is told to, and says so', async () => {
    const { policy, log } = example(undefined, { erase: { release: ['/input/scopes/1', '/result/nothing'] } })
    await policy.decide('release', { scopes: ['a', 'b', 'c'] })
    expect(log[0].input).toEqual({ scopes: ['a', 'c'] })
    expect(log[0].result).toEqual({ scopes: ['a', 'b', 'c'] })
    expect(log[0].erased).toEqual(['/input/scopes/1'])
  })

  it('understands escaped pointers, and leaves the original alone', () => {
    const entry = {
      decision_id: 'd',
      path: 'p',
      input: { 'a/b': { 'c~d': 1, keep: 2 } },
      timestamp: 't',
      labels: {},
      metrics: { timer_rego_query_eval_ns: 0 },
    }
    expect(erase(entry, ['/input/a~1b/c~0d']).input).toEqual({ 'a/b': { keep: 2 } })
    expect(entry.input['a/b']).toHaveProperty('c~d')
  })

  it('keeps deciding when a logger fails', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const kept: DecisionLogEntry[] = []
    const policy = createPolicy<Example>({
      package: 'example/policy',
      builtIn,
      loggers: [() => { throw new Error('disk full') }, (entry) => void kept.push(entry)],
    })
    expect(await policy.decide('authz', { user: 'alice' })).toEqual({ allow: true })
    expect(kept).toHaveLength(1)
    expect(error).toHaveBeenCalled()
  })

  it('can go out as JSON lines', async () => {
    const lines: string[] = []
    const policy = createPolicy<Example>({ package: 'p', builtIn, loggers: [jsonLinesLogger((line) => lines.push(line))] })
    await policy.decide('authz', { user: 'alice' })
    expect(JSON.parse(lines[0])).toMatchObject({ path: 'p/authz', result: { allow: true } })
  })
})

describe('an OPA server', () => {
  let server: http.Server | undefined
  const serve = async (handler: http.RequestListener) => {
    server = http.createServer(handler)
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve))
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  }
  afterEach(() => {
    server?.close()
    server = undefined
  })

  it('is asked each decision at its data API', async () => {
    const asked: string[] = []
    const url = await serve(async (req, res) => {
      let body = ''
      for await (const chunk of req) body += chunk
      asked.push(req.url!)
      res.end(JSON.stringify({ result: { allow: JSON.parse(body).input.user === 'bob' } }))
    })
    const { policy, log } = example({ engine: 'server', url })
    expect(await policy.decide('authz', { user: 'bob' })).toEqual({ allow: true })
    expect(asked).toEqual(['/v1/data/example/policy/authz'])
    expect(log[0].labels).toMatchObject({ engine: 'server', revision: `server ${url}` })
  })

  it('without the rule, or unreachable, is a decision not made', async () => {
    const url = await serve((_req, res) => res.end('{}'))
    const { policy, log } = example({ engine: 'server', url })
    await expect(policy.decide('release', { scopes: [] })).rejects.toThrow(PolicyUnavailableError)
    expect(log[0].error).toMatch(/example\/policy\/release rule has no value/)

    server!.close()
    await expect(policy.decide('authz', { user: 'bob' })).rejects.toThrow(PolicyUnavailableError)
  })
})

describe.skipIf(!hasOpa)("the organization's bundle", () => {
  const organization = keyPair()
  let signed: Uint8Array
  let file: string

  beforeAll(() => {
    signed = buildBundle(organization.privatePem)
    file = path.join(mkdtempSync(path.join(tmpdir(), 'fg-policy-')), 'policy.tar.gz')
    writeFileSync(file, signed)
  })

  const trusted = (source: string | Uint8Array): PolicySource => ({
    engine: 'bundle',
    source,
    publicKey: organization.publicPem,
  })

  it('answers in this process, reading its settings', async () => {
    const { policy, log } = example(trusted(file))
    expect(policy.engine).toBe('bundle')
    // Carol is allowed by the organization's settings; the built-in rule would refuse her.
    expect(await policy.decide('authz', { user: 'carol' })).toEqual({ allow: true })
    expect(await policy.decide('authz', { user: 'bob' })).toEqual({ allow: false })
    expect(await policy.decide('release', { scopes: ['a', 'secret'] })).toEqual({
      scopes: ['a'],
      reasons: { secret: 'Nobody gets the secret.' },
    })
    expect(log[0].labels).toMatchObject({ engine: 'bundle', revision: '2026.10.01' })
  })

  it('leaves what it has no rule for to the built-in rules', async () => {
    const { policy, log } = example(trusted(signed))
    expect(await policy.decide('greet', { name: 'Ada' })).toEqual({ greeting: 'Hello, Ada' })
    expect(log[0].labels).toMatchObject({ engine: 'builtin', revision: 'builtin' })
  })

  it('is disclosed', async () => {
    const disclosure = await example(trusted(signed)).policy.disclose()
    expect(disclosure).toMatchObject({ revision: '2026.10.01', signature: { algorithm: 'ES256' } })
    expect(disclosure?.packages[0].decisions.map((decision) => decision.name)).toEqual(['authz', 'release'])
  })

  it('from a URL', async () => {
    const server = http.createServer((_req, res) => res.end(signed))
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/policy.tar.gz`
    expect(await example(trusted(url)).policy.decide('authz', { user: 'alice' })).toEqual({ allow: true })
    server.close()
  })

  it("refused, decides nothing — not even what the built-in rules would — and says why", async () => {
    const { policy, log } = example({ engine: 'bundle', source: signed, publicKey: keyPair().publicPem })
    await expect(policy.decide('greet', { name: 'Ada' })).rejects.toThrow(PolicyUnavailableError)
    expect(log[0]).toMatchObject({
      error: "The bundle's signature is not the organization's.",
      labels: { engine: 'bundle', revision: 'unavailable' },
    })
    await expect(policy.disclose()).rejects.toThrow("The bundle's signature is not the organization's.")

    const missing = example({ engine: 'bundle', source: '/nowhere/policy.tar.gz', publicKey: organization.publicPem })
    await expect(missing.policy.decide('authz', { user: 'alice' })).rejects.toThrow(PolicyUnavailableError)
  })

  it('unsigned, runs only when allowed', async () => {
    const unsigned = buildBundle()
    await expect(
      example({ engine: 'bundle', source: unsigned, publicKey: organization.publicPem }).policy.decide('authz', { user: 'alice' })
    ).rejects.toThrow(PolicyUnavailableError)
    const allowed = example({ engine: 'bundle', source: unsigned, allowUnsigned: true })
    expect(await allowed.policy.decide('authz', { user: 'alice' })).toEqual({ allow: true })
  })
})

describe('the shared settings', () => {
  it('pick the bundle, a server, or neither', () => {
    expect(policySourceFromEnv({})).toBeUndefined()
    expect(policySourceFromEnv({ FG_POLICY_BUNDLE: ' ', FG_POLICY_OPA_URL: '' })).toBeUndefined()
    expect(policySourceFromEnv({ FG_POLICY_BUNDLE: 'policies.tar.gz', FG_POLICY_PUBLIC_KEY: 'KEY' })).toEqual({
      engine: 'bundle',
      source: 'policies.tar.gz',
      publicKey: 'KEY',
    })
    expect(policySourceFromEnv({ FG_POLICY_OPA_URL: 'http://opa:8181' })).toEqual({ engine: 'server', url: 'http://opa:8181' })
    expect(policySourceFromEnv({ FG_POLICY_BUNDLE: 'none' })).toBeUndefined()
  })

  it('refuse a bundle nobody can check, unless told to', () => {
    expect(() => policySourceFromEnv({ FG_POLICY_BUNDLE: 'policies.tar.gz' })).toThrow(/FG_POLICY_PUBLIC_KEY/)
    expect(policySourceFromEnv({ FG_POLICY_BUNDLE: 'policies.tar.gz', FG_POLICY_ALLOW_UNSIGNED: 'true' })).toEqual({
      engine: 'bundle',
      source: 'policies.tar.gz',
      allowUnsigned: true,
    })
    expect(() => policySourceFromEnv({ FG_POLICY_BUNDLE: 'a', FG_POLICY_OPA_URL: 'b' })).toThrow(/not both/)
  })
})
