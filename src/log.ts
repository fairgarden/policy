import type { DecisionLogEntry, DecisionLogger } from './types.ts'

const unescape = (segment: string) => segment.replace(/~1/g, '/').replace(/~0/g, '~')

/**
 * Remove what a JSON pointer names from a copy of `value`. Returns whether
 * there was anything there.
 */
const removePointer = (value: Record<string, unknown>, pointer: string): boolean => {
  const segments = pointer.split('/').slice(1).map(unescape)
  const last = segments.pop()
  if (last === undefined) return false
  let parent: unknown = value
  for (const segment of segments) {
    if (!parent || typeof parent !== 'object') return false
    parent = (parent as Record<string, unknown>)[segment]
  }
  if (!parent || typeof parent !== 'object' || !(last in parent)) return false
  if (Array.isArray(parent)) parent.splice(Number(last), 1)
  else delete (parent as Record<string, unknown>)[last]
  return true
}

/**
 * The entry with every pointer's value removed, and the pointers that had one
 * listed in `erased`, as OPA's own decision log masking does. Pointers are
 * relative to the entry: `/input/claims`, `/result/claims/membership/roles`.
 */
export const erase = (entry: DecisionLogEntry, pointers: readonly string[] = []): DecisionLogEntry => {
  if (pointers.length === 0) return entry
  // Through JSON rather than structuredClone: a rule may answer with part of
  // its input, and a shared object would be erased from both.
  const copy = JSON.parse(JSON.stringify(entry)) as DecisionLogEntry & Record<string, unknown>
  const erased = pointers.filter((pointer) => removePointer(copy, pointer))
  return erased.length > 0 ? { ...copy, erased: [...(copy.erased ?? []), ...erased] } : copy
}

/**
 * Each decision as one line of JSON, by default on standard output, where a
 * log drain — Vercel's, a container runtime's — can pick it up.
 */
export const jsonLinesLogger =
  (write: (line: string) => void = (line) => process.stdout.write(`${line}\n`)): DecisionLogger =>
  (entry) =>
    write(JSON.stringify(entry))

/** Record an entry everywhere it should go; a logger failing costs only its copy. */
export const record = async (loggers: readonly DecisionLogger[], entry: DecisionLogEntry) => {
  const results = await Promise.allSettled(loggers.map(async (logger) => logger(entry)))
  for (const result of results) {
    if (result.status === 'rejected') console.error('[policy] a decision log failed', result.reason)
  }
}
