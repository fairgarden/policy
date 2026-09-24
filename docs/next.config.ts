import { realpathSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import createMDX from '@next/mdx'
import type { NextConfig } from 'next'

// Turbopack resolves nothing outside its root, which it puts at the nearest
// lockfile or repository: this module's own. Installed from a distribution,
// `next` and the other dependencies live in the distribution's store above
// it, so the root is the directory whose node_modules holds the `next` this
// site resolves: the module on its own, or the distribution around it.
const nextPackage = realpathSync(
  createRequire(path.join(process.cwd(), 'package.json')).resolve('next/package.json')
)
const installRoot = nextPackage.slice(0, nextPackage.indexOf(`${path.sep}node_modules${path.sep}`))

const nextConfig: NextConfig = {
  // `.mdx` is not a route on its own; Next only picks these up once the
  // extension is listed here and the loader below is attached.
  pageExtensions: ['ts', 'tsx', 'mdx'],
  turbopack: { root: installRoot },
}

// Tables are GitHub-flavoured Markdown. The plugin is named rather than
// imported, so Turbopack can hand it to its MDX loader.
export default createMDX({ options: { remarkPlugins: ['remark-gfm'] } })(nextConfig)
