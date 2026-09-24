import type { JWK } from 'jose'

/**
 * The decisions a service makes, by name: what each is asked, and what it
 * answers.
 *
 * ```ts
 * type IdDecisions = {
 *   authz: { input: AuthorizationInput; result: { allow: boolean; reason?: string } }
 *   release: { input: ReleaseInput; result: { scopes: string[]; reasons?: Record<string, string> } }
 * }
 * ```
 */
export type Decisions = Record<string, { input: unknown; result: unknown }>

/**
 * Where Rego comes from, when it is not the built-in rules.
 *
 * A community's policy is a bundle built from the distribution's repository
 * (`fg-dist policy build`) and run by each service deployed from it. A bundle
 * from anywhere else runs only when it is signed by the organization's key.
 */
export type PolicySource =
  | {
      engine: 'bundle'
      /** The bundle: a path, an https URL, or the bytes. */
      source: string | Uint8Array
      /**
       * The organization's public key: PEM, a JWK, or a JWK Set while a key
       * is being replaced — as text, base64, or parsed.
       */
      publicKey?: PublicKeys
      /** Run a bundle nobody signed. Only for writing policy locally. */
      allowUnsigned?: boolean
    }
  /** An OPA server's data API: the server loads and checks the bundle itself. */
  | { engine: 'server'; url: string }

export type PublicKeys = string | JWK | { keys: JWK[] }

export type EngineName = 'builtin' | 'bundle' | 'server'

/**
 * One decision, as Open Policy Agent logs its own, so anything that reads
 * OPA's decision logs reads these.
 */
export interface DecisionLogEntry {
  decision_id: string
  /** The rule asked, as a path: `fairgarden/id/authz`. */
  path: string
  input?: unknown
  /** Absent when the decision could not be made; `error` says why. */
  result?: unknown
  error?: string
  /** RFC 3339. */
  timestamp: string
  /**
   * `engine` and `revision` — which rules answered: `builtin`, or the
   * bundle's revision — plus whatever the service adds.
   */
  labels: Record<string, string>
  /** JSON pointers to what was removed before logging, such as `/input/claims`. */
  erased?: string[]
  metrics: { timer_rego_query_eval_ns: number }
}

/** Where decisions are recorded. Awaited, so a serverless function does not end first. */
export type DecisionLogger = (entry: DecisionLogEntry) => void | Promise<void>
