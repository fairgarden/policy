import { randomUUID } from 'node:crypto'
import { loadEngine, type Engine } from './engines.ts'
import type { Disclosure } from './disclose.ts'
import { erase, record } from './log.ts'
import type { DecisionLogEntry, DecisionLogger, Decisions, EngineName, PolicySource } from './types.ts'

export type { DecisionLogEntry, DecisionLogger, Decisions, EngineName, PolicySource, PublicKeys } from './types.ts'
export { erase, jsonLinesLogger } from './log.ts'
export { BundleRejectedError, readBundle, type Bundle, type BundleTrust, type Manifest } from './bundle.ts'
export { disclose, type DisclosedPackage, type Disclosure, type RelatedResource } from './disclose.ts'
export type { Layer } from './layers.ts'
export { policySourceFromEnv } from './env.ts'
export { DEPLOYMENT_BUNDLE, deploymentBundle } from './deployment.ts'

export interface PolicyOptions<D extends Decisions> {
  /** The Rego package the decisions are rules in, as a path or dotted: `fairgarden/id`. */
  package: string
  /** The organization's Rego. Without it, the built-in rules answer. */
  source?: PolicySource
  /**
   * The rules in TypeScript, for when there is no Rego: a service works the
   * same without a policy, and a policy only has to write the decisions it
   * disagrees with — any the bundle has no rule for are answered here.
   */
  builtIn: { [K in keyof D]: (input: D[K]['input']) => D[K]['result'] | Promise<D[K]['result']> }
  /** Where every decision is recorded. */
  loggers?: DecisionLogger[]
  /** Added to every entry's labels, such as `{ service: 'id' }`. */
  labels?: Record<string, string>
  /** What to leave out of the log, per decision, as JSON pointers into the entry. */
  erase?: { [K in keyof D]?: string[] }
  /**
   * Called for each revision of the organization's policy this runs, until
   * it succeeds, to keep it — `drizzleRevisions(...).record` — so every
   * decision can be traced to the rules that made it. A failure is reported
   * and tried again with the next decision; it never stops one.
   */
  onRevision?: (disclosure: Disclosure) => void | Promise<void>
  /** How long an OPA server gets to answer. Default 2 seconds. */
  timeoutMs?: number
  fetch?: typeof fetch
}

export interface Policy<D extends Decisions> {
  /**
   * Ask a decision, and record it. Throws `PolicyUnavailableError` when it
   * cannot be made — the rules are missing, the server is down — which a
   * caller should take as no.
   */
  decide<K extends keyof D & string>(decision: K, input: D[K]['input']): Promise<D[K]['result']>
  /**
   * The organization's policy, for showing the people it governs: its
   * revision, who signed it, what each decision is for, and the Rego itself.
   * Undefined when the built-in rules answer, or an OPA server holds the
   * rules. Throws when the bundle was refused — unsigned, or not signed by
   * the organization — and why.
   */
  disclose(): Promise<Disclosure | undefined>
  readonly engine: EngineName
}

/** How long a policy that would not load is left before it is tried again. */
const RETRY_AFTER_MS = 30_000

/** A decision that could not be made. Treat it as no. */
export class PolicyUnavailableError extends Error {
  readonly path: string

  constructor(path: string, cause: unknown) {
    super(`The ${path} decision could not be made`, { cause })
    this.name = 'PolicyUnavailableError'
    this.path = path
  }
}

/**
 * A service's decisions: built-in rules, or its community organization's
 * Open Policy Agent Rego — the bundle its deployment was built with, run in
 * this process, or an OPA server — with every decision recorded for audits.
 *
 * ```ts
 * const policy = createPolicy<IdDecisions>({
 *   package: 'fairgarden/id',
 *   source: policySourceFromEnv(),
 *   builtIn: { authz: builtInAuthz, release: builtInRelease },
 *   loggers: [databaseLogger],
 * })
 * const { allow } = await policy.decide('authz', input)
 * ```
 */
export const createPolicy = <D extends Decisions>(options: PolicyOptions<D>): Policy<D> => {
  const pkg = options.package.replace(/\./g, '/')
  const engineName: EngineName = options.source?.engine ?? 'builtin'
  const timeoutMs = options.timeoutMs ?? 2_000
  let loaded: Promise<Engine> | undefined
  let failedAt = 0
  let kept: string | undefined

  // A policy that would not load is tried again after a while, not for every
  // decision: a refused bundle stays refused, and an unreachable URL is not
  // asked again at once.
  const engine = () => {
    if (loaded && failedAt && Date.now() - failedAt > RETRY_AFTER_MS) loaded = undefined
    return (loaded ??= loadEngine(options.source!, timeoutMs, options.fetch ?? fetch).then(
      (loadedEngine) => {
        failedAt = 0
        return loadedEngine
      },
      (error: unknown) => {
        failedAt = Date.now()
        throw error
      }
    ))
  }

  // Keep each revision once. A failure — the table not migrated yet, say — is
  // reported and tried again with the next decision; a slow store waits no
  // longer than an OPA server would.
  const keep = async (loadedEngine: Engine) => {
    if (!options.onRevision || !loadedEngine.disclosure || kept === loadedEngine.revision) return
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      await Promise.race([
        options.onRevision(loadedEngine.disclosure),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`no answer in ${timeoutMs}ms`)), timeoutMs)
        }),
      ])
      kept = loadedEngine.revision
    } catch (error) {
      console.error(`[policy] could not keep revision ${loadedEngine.revision}; trying again next time`, error)
    } finally {
      clearTimeout(timer)
    }
  }

  return {
    engine: engineName,
    async disclose() {
      if (!options.source) return undefined
      const loadedEngine = await engine()
      await keep(loadedEngine)
      return loadedEngine.disclosure
    },
    async decide(decision, input) {
      const path = `${pkg}/${decision}`
      const started = process.hrtime.bigint()
      let answeredBy = engineName
      // Until a bundle loads, nobody knows which revision it is.
      let revision = options.source ? 'unavailable' : 'builtin'
      let result: unknown
      let failure: unknown

      try {
        const loadedEngine = options.source ? await engine() : undefined
        if (loadedEngine) await keep(loadedEngine)
        if (loadedEngine?.decides(path)) {
          revision = loadedEngine.revision
          result = await loadedEngine.evaluate(path, input)
          if (result === undefined) throw new Error(`the policy's ${path} rule has no value for this input`)
        } else {
          answeredBy = 'builtin'
          revision = 'builtin'
          result = await options.builtIn[decision](input)
        }
      } catch (error) {
        failure = error
      }

      const entry: DecisionLogEntry = {
        decision_id: randomUUID(),
        path,
        input,
        ...(failure === undefined
          ? { result }
          : { error: failure instanceof Error ? failure.message : String(failure) }),
        timestamp: new Date().toISOString(),
        labels: { ...options.labels, engine: answeredBy, revision },
        metrics: { timer_rego_query_eval_ns: Number(process.hrtime.bigint() - started) },
      }
      await record(options.loggers ?? [], erase(entry, options.erase?.[decision]))

      if (failure !== undefined) throw new PolicyUnavailableError(path, failure)
      return result as D[typeof decision]['result']
    },
  }
}
