import { beforeAll, describe, expect, it } from 'vitest'
import { BundleRejectedError, disclose, readBundle } from '../src/index.ts'
import { untar } from '../src/tar.ts'
import { buildBundle, hasOpa, keyPair, tar } from './helpers/bundles.ts'

describe.skipIf(!hasOpa)('a signed bundle', () => {
  const organization = keyPair()
  const stranger = keyPair('rsa')
  let signed: Uint8Array
  let unsigned: Uint8Array

  beforeAll(() => {
    signed = buildBundle(organization.privatePem)
    unsigned = buildBundle()
  })

  const repack = (change: (files: Map<string, Uint8Array>) => void) => {
    const files = new Map<string, Uint8Array>(untar(signed))
    change(files)
    return tar(files)
  }

  it("is read when the signature is the organization's", async () => {
    const bundle = await readBundle(signed, { publicKey: organization.publicPem })
    expect(bundle.revision).toBe('2026.10.01')
    expect(bundle.signature).toEqual({ keyId: expect.any(String), algorithm: 'ES256' })
    // The organization's settings over the service's.
    expect(bundle.data).toEqual({ example: { settings: { allowed: ['alice', 'carol'], withhold: {} } } })
    expect(bundle.wasm.byteLength).toBeGreaterThan(0)
  })

  it('takes the key as PEM, base64, a JWK, or a key set while one key replaces another', async () => {
    const { keyId } = (await readBundle(signed, { publicKey: organization.publicPem })).signature!
    for (const publicKey of [
      Buffer.from(organization.publicPem).toString('base64'),
      JSON.stringify(organization.publicJwk),
      { keys: [stranger.publicJwk, organization.publicJwk] },
      JSON.stringify({ keys: [organization.publicJwk, stranger.publicJwk] }),
    ]) {
      expect((await readBundle(signed, { publicKey })).signature?.keyId).toBe(keyId)
    }
  })

  it("is refused when the signature is anyone else's", async () => {
    await expect(readBundle(signed, { publicKey: stranger.publicPem })).rejects.toThrow(
      new BundleRejectedError("The bundle's signature is not the organization's.")
    )
    await expect(readBundle(signed, { publicKey: { keys: [stranger.publicJwk] } })).rejects.toThrow(BundleRejectedError)
  })

  it('is refused when anything in it changed after signing', async () => {
    const publicKey = organization.publicPem
    // What members read is what was signed, too: the rules can't be disclosed as something they are not.
    const source = 'sources/policies/example/secret.rego.txt'
    const edited = repack((files) => {
      const rego = Buffer.from(files.get(source)!).toString().replace('Nobody', 'Everybody')
      expect(rego).toContain('Everybody')
      files.set(source, Buffer.from(rego))
    })
    await expect(readBundle(edited, { publicKey })).rejects.toThrow(`${source} was changed after it was signed.`)

    const settings = repack((files) => files.set('data.json', Buffer.from('{"example":{"settings":{"allowed":["mallory"],"withhold":{}}}}')))
    await expect(readBundle(settings, { publicKey })).rejects.toThrow('data.json was changed after it was signed.')

    const added = repack((files) => files.set('example/extra.rego', Buffer.from('package example.extra')))
    await expect(readBundle(added, { publicKey })).rejects.toThrow('example/extra.rego is in the bundle but was not signed.')

    const removed = repack((files) => files.delete('policies/example/secret.rego'))
    await expect(readBundle(removed, { publicKey })).rejects.toThrow('policies/example/secret.rego was signed but is missing.')
  })

  it('without a signature, or a key to check one, is only read when allowed', async () => {
    await expect(readBundle(unsigned, { publicKey: organization.publicPem })).rejects.toThrow('The bundle is not signed.')
    await expect(readBundle(signed)).rejects.toThrow('no public key is configured')
    expect((await readBundle(unsigned, { allowUnsigned: true })).signature).toBeUndefined()
  })

  it('discloses what it decides, in the words the organization wrote, and where each rule came from', async () => {
    const disclosure = disclose(await readBundle(signed, { publicKey: organization.publicPem }))
    expect(disclosure).toMatchObject({
      revision: '2026.10.01',
      signature: { algorithm: 'ES256' },
      organization: { organization: 'Example Club', source: 'https://example.org/club/policy' },
      layers: [
        { path: 'base', role: 'base', package: '@fairgarden/policy', version: expect.any(String) },
        { path: 'policies', role: 'organization' },
      ],
      data: { example: { settings: { allowed: ['alice', 'carol'] } } },
    })
    expect(disclosure.organization).not.toHaveProperty('layers')
    expect(disclosure.packages).toHaveLength(1)
    const [pkg] = disclosure.packages
    expect(pkg).toMatchObject({
      name: 'example.policy',
      title: 'The example service',
      description: 'What the example service may do, and for whom.',
      related: [{ ref: 'https://example.org/club/bylaws', description: "The club's bylaws" }],
      decisions: [
        {
          name: 'authz',
          path: 'example/policy/authz',
          title: 'Who may act',
          description: 'Only the people the club allows.',
          related: [{ ref: 'https://example.org/club/bylaws#article-2', description: 'Bylaws, Article II' }],
        },
        { name: 'release', path: 'example/policy/release', title: 'What is shared', related: [] },
      ],
    })
    // The rules as written, but not their tests: those stay in the repository.
    expect(pkg.sources.map(({ path, layer }) => ({ path, layer }))).toEqual([
      { path: 'base/example/policy.rego', layer: 'base' },
      { path: 'policies/example/secret.rego', layer: 'policies' },
    ])
    expect(pkg.sources[1].text).toContain('Nobody gets the secret.')
  })
})
