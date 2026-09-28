import { createSitemap } from '@fairgarden/docs/createSitemap'
import Overview from '../(lib)/overview/page.mdx'
import Reference from '../(lib)/reference/page.mdx'

// Sections in navigation order, each a section index the docs engine keeps.
export const sitemap = createSitemap(import.meta.url, { Overview, Reference })
