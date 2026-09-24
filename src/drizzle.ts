import { desc, eq } from 'drizzle-orm'
import { bigint, index, jsonb, pgTable, text, timestamp, type PgDatabase, type PgQueryResultHKT } from 'drizzle-orm/pg-core'
import type { Disclosure } from './disclose.ts'
import type { DecisionLogEntry, DecisionLogger } from './types.ts'

/**
 * A decision log kept in Postgres, through Drizzle: one table per service,
 * all the same shape, so an audit reads every service's decisions the same
 * way.
 *
 * ```ts
 * // lib/schema.ts
 * export const policyDecisions = decisionLogTable('id_policy_decisions')
 * ```
 */
export const decisionLogTable = (name: string) =>
  pgTable(
    name,
    {
      /** The entry's `decision_id`. */
      id: text('id').primaryKey(),
      path: text('path').notNull(),
      /** Whose decision it was — `input.user.name`, unless told otherwise — to find it by. */
      subject: text('subject'),
      input: jsonb('input'),
      result: jsonb('result'),
      error: text('error'),
      labels: jsonb('labels').$type<Record<string, string>>().notNull(),
      erased: jsonb('erased').$type<string[]>(),
      evaluationNs: bigint('evaluation_ns', { mode: 'number' }).notNull(),
      decidedAt: timestamp('decided_at', { withTimezone: true }).notNull(),
    },
    (table) => [
      index(`${name}_subject`).on(table.subject, table.decidedAt.desc()),
      index(`${name}_decided_at`).on(table.decidedAt),
    ]
  )

export type DecisionLogTable = ReturnType<typeof decisionLogTable>
export type DecisionLogRow = DecisionLogTable['$inferSelect']

// Any Drizzle Postgres database, whatever its driver and schema.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyDatabase = PgDatabase<PgQueryResultHKT, any, any>

/** Who a decision was about, by default: the input's `user.name`. */
const defaultSubject = (entry: DecisionLogEntry): string | null => {
  const user = (entry.input as { user?: { name?: unknown } } | undefined)?.user
  return typeof user?.name === 'string' ? user.name : null
}

export const toRow = (
  entry: DecisionLogEntry,
  subject: string | null = defaultSubject(entry)
): DecisionLogTable['$inferInsert'] => ({
  id: entry.decision_id,
  path: entry.path,
  subject,
  input: entry.input ?? null,
  result: entry.result ?? null,
  error: entry.error ?? null,
  labels: entry.labels,
  erased: entry.erased ?? null,
  evaluationNs: entry.metrics.timer_rego_query_eval_ns,
  decidedAt: new Date(entry.timestamp),
})

/** A row back into the entry OPA would have logged, for exporting. */
export const toEntry = (row: DecisionLogRow): DecisionLogEntry => ({
  decision_id: row.id,
  path: row.path,
  ...(row.input !== null ? { input: row.input } : {}),
  ...(row.result !== null ? { result: row.result } : {}),
  ...(row.error !== null ? { error: row.error } : {}),
  timestamp: row.decidedAt.toISOString(),
  labels: row.labels,
  ...(row.erased ? { erased: row.erased } : {}),
  metrics: { timer_rego_query_eval_ns: row.evaluationNs },
})

/**
 * Record decisions in `table`. `database` is called for each, so it can be
 * the service's lazily opened connection.
 */
export const drizzleLogger = (
  database: () => AnyDatabase | Promise<AnyDatabase>,
  table: DecisionLogTable,
  { subject = defaultSubject }: { subject?: (entry: DecisionLogEntry) => string | null } = {}
): DecisionLogger =>
  async (entry) => {
    await (await database()).insert(table).values(toRow(entry, subject(entry)))
  }

/** Newest first, for reading a log back. */
export const newestFirst = (table: DecisionLogTable) => [desc(table.decidedAt), desc(table.id)]

/**
 * Every revision of the policy a service has run, kept whole, so a decision
 * logged under a revision can be read beside the rules that made it —
 * however long ago, and however many deploys since.
 *
 * ```ts
 * // lib/schema.ts
 * export const policyRevisions = revisionTable('id_policy_revisions')
 * ```
 */
export const revisionTable = (name: string) =>
  pgTable(name, {
    /** The bundle's revision, as decisions are labelled with it. */
    revision: text('revision').primaryKey(),
    disclosure: jsonb('disclosure').$type<Disclosure>().notNull(),
    /** When this service first ran it. */
    firstUsedAt: timestamp('first_used_at', { withTimezone: true }).notNull().defaultNow(),
  })

export type RevisionTable = ReturnType<typeof revisionTable>

/**
 * Keep revisions in `table`: pass `record` as `createPolicy`'s `onRevision`,
 * and read one back with `find`.
 */
export const drizzleRevisions = (database: () => AnyDatabase | Promise<AnyDatabase>, table: RevisionTable) => ({
  async record(disclosure: Disclosure) {
    await (await database())
      .insert(table)
      .values({ revision: disclosure.revision, disclosure })
      .onConflictDoNothing()
  },
  async find(revision: string): Promise<(Disclosure & { firstUsedAt: Date }) | undefined> {
    const [row] = await (await database()).select().from(table).where(eq(table.revision, revision))
    return row ? { ...row.disclosure, firstUsedAt: row.firstUsedAt } : undefined
  },
})
