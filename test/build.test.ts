import { cpSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createPolicy, readBundle } from '../src/index.ts'
import { buildBundle, fixtures, hasOpa } from './helpers/bundles.ts'

const revisionOf = async (archive: Uint8Array) => (await readBundle(archive, { allowUnsigned: true })).revision

describe.skipIf(!hasOpa)('a build', () => {
  it('names each revision by what is in it, after the release it belongs to', async () => {
    const env = { GITHUB_SHA: 'a'.repeat(40) }
    const first = buildBundle(undefined, { revision: false, env })
    const revision = await revisionOf(first)
    // The version in the nearest package.json, and a digest of the rules and settings.
    expect(revision).toMatch(/^\d+\.\d+\.\d+[\w.-]*\+[0-9a-f]{12}$/)
    // The same policy, built again from another commit, is the same revision.
    expect(await revisionOf(buildBundle(undefined, { revision: false, env: { GITHUB_SHA: 'b'.repeat(40) } }))).toBe(revision)

    // A changed setting is a new one.
    const changed = mkdtempSync(path.join(tmpdir(), 'fg-policy-changed-'))
    cpSync(fixtures, changed, { recursive: true })
    writeFileSync(path.join(changed, 'policies/example/settings/data.json'), '{"allowed":["alice"]}')
    expect(await revisionOf(buildBundle(undefined, { revision: false, cwd: changed }))).not.toBe(revision)
  })

  it('records the commit it was built from', async () => {
    const bundle = await readBundle(buildBundle(undefined, { env: { GITHUB_SHA: 'c'.repeat(40) } }), {
      allowUnsigned: true,
    })
    expect(bundle.manifest.metadata).toMatchObject({ commit: 'c'.repeat(40) })
  })
})

describe.skipIf(!hasOpa)('a service', () => {
  const saved = process.cwd()
  afterEach(() => {
    process.chdir(saved)
    vi.resetModules()
  })

  it("runs the policy its deployment was built with, and keeps each revision it runs", async () => {
    const project = mkdtempSync(path.join(tmpdir(), 'fg-policy-project-'))
    mkdirSync(path.join(project, '.policy'))
    writeFileSync(path.join(project, '.policy/policies.tar.gz'), buildBundle())
    process.chdir(project)

    const { policySourceFromEnv } = await import('../src/index.ts')
    const source = policySourceFromEnv({})
    // Built from the repository, so it needs no signature.
    expect(source).toMatchObject({ engine: 'bundle', allowUnsigned: true })

    const kept = vi.fn()
    const policy = createPolicy<{ authz: { input: { user: string }; result: { allow: boolean } } }>({
      package: 'example/policy',
      source,
      builtIn: { authz: () => ({ allow: false }) },
      onRevision: kept,
    })
    expect(await policy.decide('authz', { user: 'carol' })).toEqual({ allow: true })
    await policy.decide('authz', { user: 'alice' })
    expect(kept).toHaveBeenCalledTimes(1)
    expect(kept.mock.calls[0][0]).toMatchObject({ revision: '2026.10.01', organization: { organization: 'Example Club' } })
  })

  it('without one, has the built-in rules', async () => {
    process.chdir(mkdtempSync(path.join(tmpdir(), 'fg-policy-project-')))
    const { policySourceFromEnv } = await import('../src/index.ts')
    expect(policySourceFromEnv({})).toBeUndefined()
  })
})

describe('fetching opa', () => {
  const saved = process.cwd()
  afterEach(() => {
    process.chdir(saved)
    vi.unstubAllEnvs()
    vi.unstubAllGlobals()
    vi.resetModules()
  })

  it('refuses a download that is not the release it pinned', async () => {
    vi.stubEnv('OPA', '')
    vi.stubEnv('PATH', '')
    process.chdir(mkdtempSync(path.join(tmpdir(), 'fg-policy-opa-')))
    mkdirSync('node_modules')
    vi.stubGlobal('fetch', async () => new Response('not opa'))
    const { findOpa, OPA_VERSION } = await import('../src/opa.ts')
    await expect(findOpa()).rejects.toThrow(`is not the opa ${OPA_VERSION} release`)
  })
})
