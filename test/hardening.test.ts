import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { hashFile } from '../src/bundle.ts'
import { createPolicy, readBundle } from '../src/index.ts'
import { findLayers } from '../src/layers.ts'
import { untar } from '../src/tar.ts'
import { buildBundle, hasOpa, keyPair, tar } from './helpers/bundles.ts'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('what a bundle is trusted with', () => {
  it('hashes numbers as written, as OPA does', () => {
    const hash = (text: string) => hashFile('data.json', Buffer.from(text))
    expect(hash('{"x":1.0}')).not.toBe(hash('{"x":1}'))
    expect(hash('{"b":1e3,"a":1}')).toBe(hash('{"a":1,"b":1e3}'))
  })

  it.skipIf(!hasOpa)('says a key is not one, rather than trying forever', async () => {
    const signed = buildBundle(keyPair().privatePem)
    for (const publicKey of ['missing.pem', Buffer.from('still not a key').toString('base64')]) {
      await expect(readBundle(signed, { publicKey })).rejects.toThrow('The public key is not PEM, a JWK or a JWK Set')
    }
  })

  it.skipIf(!hasOpa)('keeps settings out of the prototypes of this process', async () => {
    const files = new Map<string, Uint8Array>(untar(buildBundle()))
    files.set('data.json', Buffer.from('{"__proto__":{"polluted":true},"example":{"settings":{"allowed":["alice"]}}}'))
    const bundle = await readBundle(tar(files), { allowUnsigned: true })
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined()
    expect(bundle.data).toEqual({ example: { settings: { allowed: ['alice'] } } })
  })
})

describe('layers', () => {
  it('each have a place of their own, the organization keeping its name', () => {
    const root = mkdtempSync(path.join(tmpdir(), 'fg-policy-layers-'))
    const project = path.join(root, 'project')
    for (const dir of [path.join(project, 'policies'), path.join(root, 'parent', 'policies')]) mkdirSync(dir, { recursive: true })
    writeFileSync(path.join(root, 'parent', 'package.json'), '{"name":"@fair/core"}')
    const layers = findLayers('policies', [], project, ['../parent/policies'])
    expect(layers.map((layer) => [layer.role, layer.path])).toEqual([
      ['parent', '@fair/core/policies'],
      ['organization', 'policies'],
    ])
  })
})

describe.skipIf(!hasOpa)('loading a policy', () => {
  const organization = keyPair()
  type Example = { authz: { input: { user: string }; result: { allow: boolean } } }

  it('keeps trying to keep a revision until it is kept, without holding up decisions', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    let attempts = 0
    const onRevision = vi.fn(async () => {
      attempts += 1
      if (attempts === 1) throw new Error('relation "policy_revisions" does not exist')
      if (attempts === 2) await new Promise(() => undefined)
    })
    const policy = createPolicy<Example>({
      package: 'example/policy',
      source: { engine: 'bundle', source: buildBundle(organization.privatePem), publicKey: organization.publicPem },
      builtIn: { authz: () => ({ allow: false }) },
      onRevision,
      timeoutMs: 50,
    })
    for (let i = 0; i < 4; i += 1) expect(await policy.decide('authz', { user: 'alice' })).toEqual({ allow: true })
    // Failed, hung, then kept — and not asked again.
    expect(onRevision).toHaveBeenCalledTimes(3)
  })

  it('does not load a refused policy again for every decision', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const fetcher = vi.fn(async () => new Response(buildBundle(organization.privatePem)))
    const policy = createPolicy<Example>({
      package: 'example/policy',
      source: { engine: 'bundle', source: 'https://policy.example.org/policies.tar.gz', publicKey: keyPair().publicPem },
      builtIn: { authz: () => ({ allow: false }) },
      fetch: fetcher as typeof fetch,
    })
    for (let i = 0; i < 3; i += 1) await expect(policy.decide('authz', { user: 'alice' })).rejects.toThrow()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
})

describe.skipIf(!hasOpa)('testing layers', () => {
  it("runs a parent's tests on the layers beneath it, not on its own", async () => {
    const root = mkdtempSync(path.join(tmpdir(), 'fg-policy-stack-'))
    const write = (file: string, text: string) => {
      mkdirSync(path.dirname(path.join(root, file)), { recursive: true })
      writeFileSync(path.join(root, file), text)
    }
    write('base/x.rego', 'package x\n\nimport rego.v1\n\nallow if count(deny) == 0\n\ndeny contains reason if {\n\tfalse\n\treason := ""\n}\n')
    write('parent/x/parent.rego', 'package x\n\nimport rego.v1\n\ndeny contains "No mallory." if input.user == "mallory"\n')
    write('parent/x/parent_test.rego', 'package x_test\n\nimport rego.v1\n\nimport data.x\n\ntest_mallory if not x.allow with input as {"user": "mallory"}\n\ntest_alice if x.allow with input as {"user": "alice"}\n')
    write('policies/.manifest', '{}')
    const { execFileSync } = await import('node:child_process')
    const output = execFileSync(
      process.execPath,
      [path.resolve(import.meta.dirname, '../src/cli.ts'), 'test', '--base', 'base', '--parent', 'parent', '--dir', 'policies'],
      { cwd: root, stdio: 'pipe' }
    ).toString()
    expect(output).toMatch(/parent, on top of them:[\s\S]*PASS: 2\/2/)
  })
})
