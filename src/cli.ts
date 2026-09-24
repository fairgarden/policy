#!/usr/bin/env node
import { generateKeyPairSync } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'
import type { JWK } from 'jose'
import { BundleRejectedError, keyIdOf, readBundle } from './bundle.ts'
import { buildBundle, testLayers } from './build.ts'
import { disclose } from './disclose.ts'
import { findLayers } from './layers.ts'
import { OpaFailed } from './opa.ts'

/**
 * `fg-policy`: build, sign, check and test an organization's policy. Building
 * and testing need the opa CLI; a service runs what `build` writes without it.
 */

const USAGE = `Usage:
  fg-policy build [--dir DIR] [--base DIR...] [--parent DIR...] [--out FILE]
                  [--release VERSION | --revision REV] [--signing-key FILE] [--key-id ID]
      Build the organization's policy into a bundle: DIR (default policies/),
      on top of each --parent (the policy of a distribution this extends),
      on top of each --base (a service's policies/, or a glob of them such
      as 'apps/*/policies'). The Rego is compiled to WebAssembly; settings in
      data.json are merged, DIR's winning; DIR's .manifest describes it.
      Rules annotated "entrypoint: true" are the decisions.

      FILE defaults to DIR.tar.gz. The revision is VERSION (default: the
      version in the nearest package.json) and a digest of the rules and
      settings, so every change is a revision of its own; or REV, whole. Signed with --signing-key, or the PEM in
      FG_POLICY_SIGNING_KEY; the key id defaults to the key's thumbprint.

  fg-policy test [--dir DIR] [--base DIR...] [--parent DIR...]
      Run each base's tests on its own rules, then DIR's tests on them all.

  fg-policy keygen [--out FILE] [--alg ES256|RS256]
      Write a new signing key to FILE (default policy-signing-key.pem), and
      print its public half for services' FG_POLICY_PUBLIC_KEY.

  fg-policy inspect [BUNDLE] [--public-key KEY] [--allow-unsigned] [--json]
      Check BUNDLE (default policies.tar.gz) is signed by KEY (a file, or the
      key itself; default FG_POLICY_PUBLIC_KEY), and describe what it decides.

Building and testing use the opa CLI at OPA, or on the PATH, or else fetch a
pinned release of it.`

const usage = (): never => {
  console.error(USAGE)
  process.exit(1)
}

const shown = (file: string) => {
  const relative = path.relative(process.cwd(), file)
  return relative.startsWith('..') ? file : relative
}

const describe = (disclosure: ReturnType<typeof disclose>) => {
  const lines = [`Revision      ${disclosure.revision}`]
  lines.push(
    disclosure.signature
      ? `Signed        ${disclosure.signature.algorithm}, key ${disclosure.signature.keyId}`
      : 'Signed        no'
  )
  if (disclosure.commit) lines.push(`Commit        ${disclosure.commit}`)
  for (const [key, value] of Object.entries(disclosure.organization)) {
    lines.push(`${key.padEnd(14)}${typeof value === 'string' ? value : JSON.stringify(value)}`)
  }
  for (const layer of disclosure.layers) {
    const from = layer.package ? ` (${layer.package}${layer.version ? ` ${layer.version}` : ''})` : ''
    const role = { base: 'Base', parent: 'Parent', organization: 'Organization' }[layer.role]
    lines.push(`${role.padEnd(14)}${layer.path}${from}`)
  }
  for (const pkg of disclosure.packages) {
    lines.push('', `${pkg.name}${pkg.title ? ` — ${pkg.title}` : ''}`)
    for (const decision of pkg.decisions) {
      lines.push(`  ${decision.name}${decision.title ? ` — ${decision.title}` : ''}`)
    }
    if (pkg.decisions.length === 0) lines.push('  (no decisions: nothing here is annotated entrypoint: true)')
  }
  return lines.join('\n')
}

const layerOptions = {
  dir: { type: 'string', default: 'policies' },
  base: { type: 'string', multiple: true, default: [] as string[] },
  parent: { type: 'string', multiple: true, default: [] as string[] },
} as const

const build = async (args: string[]) => {
  const { values } = parseArgs({
    args,
    options: {
      ...layerOptions,
      out: { type: 'string' },
      release: { type: 'string' },
      revision: { type: 'string' },
      'signing-key': { type: 'string' },
      'key-id': { type: 'string' },
    },
  })
  const layers = findLayers(values.dir, values.base, process.cwd(), values.parent)
  const out = path.resolve(values.out ?? `${layers.at(-1)!.dir}.tar.gz`)
  const signingKey = values['signing-key'] ? readFileSync(values['signing-key'], 'utf8') : process.env.FG_POLICY_SIGNING_KEY
  const { bundle } = await buildBundle({
    layers,
    out,
    version: values.release,
    revision: values.revision,
    signingKey,
    keyId: values['key-id'],
  })
  console.log(`Wrote ${shown(out)}\n\n${describe(disclose(bundle))}`)
}

const keygen = async (args: string[]) => {
  const { values } = parseArgs({
    args,
    options: {
      out: { type: 'string', default: 'policy-signing-key.pem' },
      alg: { type: 'string', default: 'ES256' },
    },
  })
  const out = path.resolve(values.out)
  if (existsSync(out)) throw new Error(`${values.out} already exists; move it before making another.`)
  const { privateKey, publicKey } =
    values.alg === 'RS256'
      ? generateKeyPairSync('rsa', { modulusLength: 3072 })
      : values.alg === 'ES256'
        ? generateKeyPairSync('ec', { namedCurve: 'P-256' })
        : usage()
  writeFileSync(out, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })

  const jwk = publicKey.export({ format: 'jwk' }) as JWK
  const shared = { ...jwk, kid: await keyIdOf(jwk), alg: values.alg, use: 'sig' }
  console.log(`Wrote the private key to ${shown(out)}. Keep it secret: whoever has it
can sign policy the services will run. Build with it in CI as FG_POLICY_SIGNING_KEY.

Give the services the public key, as FG_POLICY_PUBLIC_KEY:

${JSON.stringify(shared)}

While replacing a key, give them both: {"keys":[<old>,<new>]}.`)
}

const inspect = async (args: string[]) => {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      'public-key': { type: 'string' },
      'allow-unsigned': { type: 'boolean', default: false },
      json: { type: 'boolean', default: false },
    },
  })
  const file = positionals[0] ?? 'policies.tar.gz'
  const key = values['public-key'] ?? process.env.FG_POLICY_PUBLIC_KEY
  const publicKey = key && existsSync(key) ? readFileSync(key, 'utf8') : key
  try {
    const disclosure = disclose(
      await readBundle(readFileSync(file), { publicKey, allowUnsigned: values['allow-unsigned'] })
    )
    console.log(values.json ? JSON.stringify(disclosure, null, 2) : `${file}\n\n${describe(disclosure)}`)
  } catch (error) {
    if (!(error instanceof BundleRejectedError)) throw error
    console.error(`${file} would be refused: ${error.message}`)
    process.exit(2)
  }
}

const test = async (args: string[]) => {
  const { values } = parseArgs({ args, options: layerOptions })
  await testLayers(findLayers(values.dir, values.base, process.cwd(), values.parent))
}

const [command, ...rest] = process.argv.slice(2)
try {
  if (command === 'build') await build(rest)
  else if (command === 'keygen') await keygen(rest)
  else if (command === 'inspect') await inspect(rest)
  else if (command === 'test') await test(rest)
  else {
    console.error(USAGE)
    process.exit(command ? 1 : 0)
  }
} catch (error) {
  if (!(error instanceof OpaFailed)) console.error(error instanceof Error ? error.message : error)
  process.exit(error instanceof OpaFailed ? error.status : 1)
}
