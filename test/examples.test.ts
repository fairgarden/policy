import { execFileSync } from 'node:child_process'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { hasOpa } from './helpers/bundles.ts'

const ROOT = path.resolve(import.meta.dirname, '..')

// The docs quote these; their tests keep them honest.
describe.skipIf(!hasOpa)('the bylaws example', () => {
  it("passes its tests, on top of the services' rules it builds on", () => {
    const run = () =>
      execFileSync(
        process.execPath,
        [path.join(ROOT, 'src/cli.ts'), 'test', '--base', 'examples/bylaws/services', '--dir', 'examples/bylaws/organization'],
        { cwd: ROOT, stdio: 'pipe' }
      )
    expect(run().toString()).toMatch(/PASS: 5\/5/)
  })
})
