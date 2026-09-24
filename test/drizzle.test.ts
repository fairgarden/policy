import { getTableConfig } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { decisionLogTable, toEntry, toRow, type DecisionLogRow } from '../src/drizzle.ts'
import type { DecisionLogEntry } from '../src/index.ts'

const entry: DecisionLogEntry = {
  decision_id: '6f1c7e2a-0000-4000-8000-000000000000',
  path: 'fairgarden/id/release',
  input: { user: { name: 'person-1' }, scopes: ['openid'] },
  result: { scopes: ['openid'] },
  timestamp: '2026-09-24T12:00:00.000Z',
  labels: { service: 'id', engine: 'builtin', revision: 'builtin' },
  erased: ['/input/claims'],
  metrics: { timer_rego_query_eval_ns: 1234 },
}

describe('a decision log in Postgres', () => {
  it('is one table per service, all the same shape', () => {
    const config = getTableConfig(decisionLogTable('acme_policy_decisions'))
    expect(config.name).toBe('acme_policy_decisions')
    expect(config.columns.map((column) => column.name).sort()).toEqual(
      ['decided_at', 'erased', 'error', 'evaluation_ns', 'id', 'input', 'labels', 'path', 'result', 'subject'].sort()
    )
    expect(config.indexes.map((index) => index.config.name).sort()).toEqual([
      'acme_policy_decisions_decided_at',
      'acme_policy_decisions_subject',
    ])
  })

  it('files each entry under whose it is, and gives it back as OPA logged it', () => {
    const row = toRow(entry)
    expect(row.subject).toBe('person-1')
    expect(toEntry({ ...row, subject: row.subject ?? null } as DecisionLogRow)).toEqual(entry)
    expect(toRow({ ...entry, input: { anonymous: true } }).subject).toBeNull()
  })

  it('keeps a failed decision as a failure', () => {
    const { result: _result, ...failed } = entry
    const back = toEntry(toRow({ ...failed, error: 'OPA answered 500' }) as DecisionLogRow)
    expect(back).toMatchObject({ error: 'OPA answered 500' })
    expect(back).not.toHaveProperty('result')
  })
})
