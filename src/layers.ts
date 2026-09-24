import { copyFileSync, existsSync, globSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import type { Manifest } from './bundle.ts'
import { sourcePath } from './bundle.ts'

/**
 * An organization's policy is built in layers, so that upgrading a service
 * brings its rules along and the organization's own choices survive it:
 *
 * - **Base layers** come with the services, as each one's `policies/`: the
 *   decisions it asks, the rules it ships, and the extension points those
 *   rules read — partial rules such as `withheld[scope]`, and settings in
 *   `data.json`. They move when the service is upgraded.
 * - **A parent layer** is the organization's policy of a distribution this
 *   one extends, as it was published: its choices, which this one builds on.
 * - **The organization's layer** is the distribution's own `policies/`: its
 *   `.manifest`, and whatever it adds to those extension points, overrides
 *   in settings, or writes anew. An upgrade does not touch it.
 *
 * Rego from every layer is compiled together, so the organization's files
 * add to a service's rules in the same package. Settings are merged, the
 * organization's winning.
 */
export interface Layer {
  /** Where it was, relative to where the bundle was built: `apps/id/policies`. */
  path: string
  role: 'base' | 'parent' | 'organization'
  /** The package it came with, and at which version. */
  package?: string
  version?: string
}

/**
 * The manifest's `metadata` keys a build writes: the layers, and the commit
 * built. The rest of `metadata` is the organization's.
 */
export const LAYERS_KEY = 'layers'
export const COMMIT_KEY = 'commit'

const packageNear = (from: string): { package?: string; version?: string } => {
  for (let dir = from; ; dir = path.dirname(dir)) {
    const file = path.join(dir, 'package.json')
    if (existsSync(file)) {
      const { name, version } = JSON.parse(readFileSync(file, 'utf8')) as { name?: string; version?: string }
      return { package: name, version }
    }
    if (path.dirname(dir) === dir) return {}
  }
}

/** Where a layer was, relative to the build; outside it, by its package. */
const layerPath = (dir: string, cwd: string) => {
  const relative = path.relative(cwd, dir).split(path.sep).join('/')
  if (relative && !relative.startsWith('..')) return relative
  const { package: name } = packageNear(dir)
  return name ? `${name}/${path.basename(dir)}` : path.basename(dir)
}

/**
 * Each layer's Rego is laid out under its path, so no two may share one: a
 * later duplicate gets a suffix, and the organization's is never the one
 * renamed.
 */
const uniquePaths = <L extends Layer>(layers: L[]): L[] => {
  const used = new Set<string>()
  const named = [...layers].reverse().map((layer) => {
    let candidate = layer.path
    for (let n = 2; used.has(candidate); n += 1) candidate = `${layer.path}-${n}`
    used.add(candidate)
    return { ...layer, path: candidate }
  })
  return named.reverse()
}

/**
 * The layers, bases first: each base is a directory or a glob of them
 * (`apps/*\/policies`); then any parents, directories; then `organization`,
 * the organization's own.
 */
export const findLayers = (
  organization: string,
  bases: string[],
  cwd = process.cwd(),
  parents: string[] = []
): Array<Layer & { dir: string }> => {
  const own = path.resolve(cwd, organization)
  if (!existsSync(own)) throw new Error(`There is no ${organization} directory.`)
  const dirs = new Set<string>()
  for (const pattern of bases) {
    const matches = /[*?[{]/.test(pattern) ? globSync(pattern, { cwd }).sort() : [pattern]
    for (const match of matches) {
      const dir = path.resolve(cwd, match)
      if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new Error(`There is no ${match} directory.`)
      if (dir !== own) dirs.add(dir)
    }
  }
  return uniquePaths([
    ...[...dirs].map((dir) => ({ dir, path: layerPath(dir, cwd), role: 'base' as const, ...packageNear(dir) })),
    ...parents.map((dir) => ({
      dir: path.resolve(cwd, dir),
      path: layerPath(path.resolve(cwd, dir), cwd),
      role: 'parent' as const,
      ...packageNear(path.resolve(cwd, dir)),
    })),
    { dir: own, path: layerPath(own, cwd), role: 'organization' as const, ...packageNear(own) },
  ])
}

/** Every file in a layer, relative and with forward slashes; nothing installed or hidden but `.manifest`. */
const filesIn = (dir: string) =>
  readdirSync(dir, { recursive: true, encoding: 'utf8' })
    .map((file) => file.split(path.sep).join('/'))
    .filter((file) => file === '.manifest' || !file.split('/').some((part) => part === 'node_modules' || part.startsWith('.')))
    .filter((file) => statSync(path.join(dir, file)).isFile())
    .sort()

const isObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value)

/** Settings are data, never prototypes. */
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

/** `over` on top of `under`: objects merge, anything else is replaced. */
const merge = (under: unknown, over: unknown): unknown =>
  isObject(under) && isObject(over)
    ? Object.fromEntries(
        [...new Set([...Object.keys(under), ...Object.keys(over)])].filter((key) => !UNSAFE_KEYS.has(key)).map((key) => [
          key,
          key in over ? merge(under[key], over[key]) : under[key],
        ])
      )
    : over

/**
 * Lay the layers out in `into`, ready for `opa build` or `opa test`: each
 * layer's Rego under its own path, settings merged at theirs, and the
 * organization's `.manifest` naming the layers. Tests come only from the
 * last layer, and only when asked for: the layers beneath it are what its
 * tests were written against, and a layer on top may change what they check.
 *
 * Returns where each layer's Rego is to be kept as written.
 */
export const assemble = (
  layers: Array<Layer & { dir: string }>,
  into: string,
  { tests = false, commit }: { tests?: boolean; commit?: string } = {}
): Array<{ name: string; from: string }> => {
  const data = new Map<string, unknown>()
  const sources: Array<{ name: string; from: string }> = []
  let manifest: Manifest = {}

  for (const layer of layers) {
    for (const file of filesIn(layer.dir)) {
      const from = path.join(layer.dir, file)
      const base = path.posix.basename(file)
      if (file === '.manifest') {
        if (layer.role === 'organization') manifest = JSON.parse(readFileSync(from, 'utf8')) as Manifest
      } else if (base === 'data.json') {
        data.set(file, merge(data.get(file), JSON.parse(readFileSync(from, 'utf8'))))
      } else if (base === 'data.yaml' || base === 'data.yml') {
        throw new Error(`${layer.path}/${file}: write settings as data.json, so layers can be merged.`)
      } else if (file.endsWith('.rego')) {
        const isTest = file.endsWith('_test.rego')
        if (isTest && !(tests && layer === layers.at(-1))) continue
        const to = path.join(into, layer.path, file)
        mkdirSync(path.dirname(to), { recursive: true })
        copyFileSync(from, to)
        if (!isTest) sources.push({ name: sourcePath(`${layer.path}/${file}`), from })
      }
    }
  }

  for (const [file, value] of data) {
    const to = path.join(into, file)
    mkdirSync(path.dirname(to), { recursive: true })
    writeFileSync(to, JSON.stringify(value))
  }
  writeFileSync(
    path.join(into, '.manifest'),
    JSON.stringify({
      ...manifest,
      metadata: {
        ...manifest.metadata,
        [LAYERS_KEY]: layers.map(({ dir: _dir, ...layer }) => layer),
        ...(commit ? { [COMMIT_KEY]: commit } : {}),
      },
    })
  )
  return sources
}
