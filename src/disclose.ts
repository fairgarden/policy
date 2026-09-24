import { parse } from 'yaml'
import { isSourcePath, type Annotations, type Bundle } from './bundle.ts'
import { COMMIT_KEY, LAYERS_KEY, type Layer } from './layers.ts'

/**
 * A policy, as the people it governs should be able to read it: who signed
 * it and which revision it is, what each decision is for in plain words, and
 * the rules themselves.
 *
 * The plain words are the organization's own, from `# METADATA` annotations in
 * the Rego — a `title` and `description` on each package and each decision.
 */
export interface Disclosure {
  revision: string
  /** Who signed it; absent for an unsigned bundle. */
  signature?: { keyId: string; algorithm: string }
  /** The manifest's `metadata`: the organization's name, where the policy is kept. */
  organization: Record<string, unknown>
  /** What it was built from: the services' rules, and the organization's on top. */
  layers: Layer[]
  /** The commit it was built from, where the build knew it. */
  commit?: string
  packages: DisclosedPackage[]
  /** The settings the rules read. */
  data: unknown
}

/** Where to read more: the article of the bylaws a rule enforces, say. */
export interface RelatedResource {
  ref: string
  description?: string
}

export interface DisclosedPackage {
  /** Dotted, as in Rego: `fairgarden.id`. */
  name: string
  title?: string
  description?: string
  related: RelatedResource[]
  decisions: Array<{
    /** The rule's name: `authz`. */
    name: string
    /** As asked: `fairgarden/id/authz`. */
    path: string
    title?: string
    description?: string
    related: RelatedResource[]
  }>
  sources: Array<{
    /** Where it was when built: `apps/id/policies/id.rego`. */
    path: string
    /** The layer it is from, by its path; absent for a bundle built without layers. */
    layer?: string
    text: string
  }>
}

interface Annotated {
  annotations: Annotations
  target: string
}

/** Every `# METADATA` block in a Rego file, and the line it annotates. */
export const metadataBlocks = (text: string): Annotated[] => {
  const lines = text.split('\n')
  const blocks: Annotated[] = []
  for (let index = 0; index < lines.length; index++) {
    if (!/^\s*#\s*METADATA\s*$/.test(lines[index])) continue
    const yaml: string[] = []
    let next = index + 1
    while (next < lines.length && /^\s*#/.test(lines[next])) {
      yaml.push(lines[next].replace(/^\s*# ?/, ''))
      next += 1
    }
    while (next < lines.length && lines[next].trim() === '') next += 1
    try {
      blocks.push({ annotations: (parse(yaml.join('\n')) ?? {}) as Annotations, target: lines[next]?.trim() ?? '' })
    } catch {
      // Not ours to judge: opa check reports malformed metadata.
    }
    index = next - 1
  }
  return blocks
}

const text = (value: unknown) => (typeof value === 'string' ? value.trim() : undefined)

/** OPA's `related_resources`: each a `{ref, description?}`, or just the ref. */
const related = (value: unknown): RelatedResource[] =>
  (Array.isArray(value) ? value : []).flatMap((resource: unknown) => {
    if (typeof resource === 'string') return [{ ref: resource }]
    const { ref, description } = (resource ?? {}) as Record<string, unknown>
    return typeof ref === 'string' ? [{ ref, ...(text(description) ? { description: text(description) } : {}) }] : []
  })

export const disclose = (bundle: Bundle): Disclosure => {
  const packages = new Map<string, DisclosedPackage>()
  const packageOf = (name: string) => {
    if (!packages.has(name)) packages.set(name, { name, related: [], decisions: [], sources: [] })
    return packages.get(name)!
  }

  const { [LAYERS_KEY]: listed, [COMMIT_KEY]: commit, ...organization } = bundle.manifest.metadata ?? {}
  const layers = Array.isArray(listed) ? (listed as Layer[]) : []
  // Longest first, so a layer inside another is matched before it.
  const layerOf = (path: string) =>
    [...layers].sort((a, b) => b.path.length - a.path.length).find((layer) => path.startsWith(`${layer.path}/`))?.path

  // The Rego as written, when the bundle keeps it; compiled rules are missing from the rest.
  const files = [...bundle.files].sort(([a], [b]) => a.localeCompare(b))
  const written = files.some(([name]) => isSourcePath(name))
  for (const [file, bytes] of files) {
    if (written ? !isSourcePath(file) : !file.endsWith('.rego')) continue
    const path = written ? file.slice('sources/'.length, -'.txt'.length) : file
    const source = Buffer.from(bytes).toString('utf8')
    const name = /^\s*package\s+([\w.]+)/m.exec(source)?.[1]
    if (!name) continue
    // Tests show how the rules behave, but they are not the rules.
    if (name.endsWith('_test')) continue
    const disclosed = packageOf(name)
    const layer = layerOf(path)
    disclosed.sources.push({ path, ...(layer ? { layer } : {}), text: source })
    for (const { annotations, target } of metadataBlocks(source)) {
      if (target.startsWith('package ')) {
        disclosed.title ??= text(annotations.title)
        disclosed.description ??= text(annotations.description)
        disclosed.related.push(...related(annotations.related_resources))
      }
    }
  }

  for (const { entrypoint, annotations = [] } of bundle.manifest.wasm ?? []) {
    const parts = entrypoint.split('/')
    const name = parts.pop()!
    const described = annotations.find((annotation) => annotation.title || annotation.description) ?? {}
    packageOf(parts.join('.')).decisions.push({
      name,
      path: entrypoint,
      title: text(described.title),
      description: text(described.description),
      related: annotations.flatMap((annotation) => related(annotation.related_resources)),
    })
  }

  return {
    revision: bundle.revision,
    ...(bundle.signature ? { signature: bundle.signature } : {}),
    organization,
    layers,
    ...(typeof commit === 'string' ? { commit } : {}),
    packages: [...packages.values()].sort((a, b) => a.name.localeCompare(b.name)),
    data: bundle.data,
  }
}
