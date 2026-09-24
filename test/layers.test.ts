import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { assemble, findLayers } from '../src/layers.ts'

const tree = (files: Record<string, string>) => {
  const root = mkdtempSync(path.join(tmpdir(), 'fg-policy-layers-'))
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, name)), { recursive: true })
    writeFileSync(path.join(root, name), text)
  }
  return root
}

describe('layers', () => {
  const root = tree({
    'apps/id/package.json': '{"name":"@example/id","version":"1.2.0"}',
    'apps/id/policies/id.rego': 'package example.id',
    'apps/id/policies/id_test.rego': 'package example.id_test',
    'apps/id/policies/example/id/settings/data.json': '{"hours":25,"offices":{"secretary":{"majority":0.5}}}',
    'apps/id/policies/node_modules/dep/x.rego': 'package installed',
    'apps/events/policies/events.rego': 'package example.events',
    'apps/web/Readme.md': 'no policies here',
    'policies/.manifest': '{"roots":["example"],"metadata":{"organization":"Example Club"}}',
    'policies/example/id/settings/data.json': '{"hours":10,"offices":{"treasurer":{"majority":0.66}}}',
    'policies/example/bylaws.rego': 'package example.id',
    'policies/example/bylaws_test.rego': 'package example.bylaws_test',
  })

  it('are the services’ policies, then the organization’s', () => {
    const layers = findLayers('policies', ['apps/*/policies'], root)
    expect(layers.map(({ dir: _dir, ...layer }) => layer)).toEqual([
      { path: 'apps/events/policies', role: 'base' },
      { path: 'apps/id/policies', role: 'base', package: '@example/id', version: '1.2.0' },
      { path: 'policies', role: 'organization' },
    ])
    expect(() => findLayers('nowhere', [], root)).toThrow('There is no nowhere directory.')
    expect(() => findLayers('policies', ['apps/web/policies'], root)).toThrow('There is no apps/web/policies directory.')
  })

  it('are laid out together, the organization’s settings winning', () => {
    const into = mkdtempSync(path.join(tmpdir(), 'fg-policy-assembled-'))
    const sources = assemble(findLayers('policies', ['apps/*/policies'], root), into)

    expect(JSON.parse(readFileSync(path.join(into, 'example/id/settings/data.json'), 'utf8'))).toEqual({
      hours: 10,
      offices: { secretary: { majority: 0.5 }, treasurer: { majority: 0.66 } },
    })
    expect(JSON.parse(readFileSync(path.join(into, '.manifest'), 'utf8'))).toEqual({
      roots: ['example'],
      metadata: {
        organization: 'Example Club',
        layers: [
          { path: 'apps/events/policies', role: 'base' },
          { path: 'apps/id/policies', role: 'base', package: '@example/id', version: '1.2.0' },
          { path: 'policies', role: 'organization' },
        ],
      },
    })
    // Each layer's Rego under its own path, so two files of the same name do not collide.
    expect(sources.map((source) => source.name)).toEqual([
      'sources/apps/events/policies/events.rego.txt',
      'sources/apps/id/policies/id.rego.txt',
      'sources/policies/example/bylaws.rego.txt',
    ])
    expect(readFileSync(path.join(into, 'policies/example/bylaws.rego'), 'utf8')).toBe('package example.id')
  })

  it('bring the organization’s tests only when testing, and never the services’', () => {
    const into = mkdtempSync(path.join(tmpdir(), 'fg-policy-assembled-'))
    assemble(findLayers('policies', ['apps/*/policies'], root), into, { tests: true })
    expect(() => readFileSync(path.join(into, 'policies/example/bylaws_test.rego'))).not.toThrow()
    expect(() => readFileSync(path.join(into, 'apps/id/policies/id_test.rego'))).toThrow()
    expect(() => readFileSync(path.join(into, 'apps/id/policies/node_modules/dep/x.rego'))).toThrow()
  })

  it('want settings as JSON, so they can be merged', () => {
    const yaml = tree({ 'policies/example/data.yaml': 'hours: 25' })
    expect(() => assemble(findLayers('policies', [], yaml), mkdtempSync(path.join(tmpdir(), 'fg-')))).toThrow(
      'policies/example/data.yaml: write settings as data.json'
    )
  })
})
