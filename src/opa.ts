import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, renameSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

/**
 * The opa CLI, which compiles and tests Rego. A service never needs it; a
 * build does. Taken from `OPA`, or the PATH, or else fetched: a pinned
 * release, checked against the checksums below before it is ever run, and
 * kept for next time. So a deployment can build its policy on a host that
 * has never heard of OPA.
 */
export const OPA_VERSION = '1.21.0'

const RELEASES: Record<string, { file: string; sha256: string }> = {
  'linux-x64': {
    file: 'opa_linux_amd64_static',
    sha256: '5eef70644868bb04d0556bcc795ee42f2ab379e73f51d1bfa30f83e1305bc9b9',
  },
  'linux-arm64': {
    file: 'opa_linux_arm64_static',
    sha256: '0ec34027c15b4d969c21d01ed570fe14fbebd508a08157043ab09f9a0dccbee6',
  },
  'darwin-x64': {
    file: 'opa_darwin_amd64',
    sha256: '0ceb96979d259b3ee31711a6b316a592b8ffcfdd4209cc37600ed85a6cd4a55c',
  },
  'darwin-arm64': {
    file: 'opa_darwin_arm64_static',
    sha256: 'f1e4da6467a2adb2846bb23eec6ea00d8c3a04786f9270bb11003d22dfd827a5',
  },
  'win32-x64': {
    file: 'opa_windows_amd64.exe',
    sha256: '1e0e9639673615fa3a6d4974b07e335e44827e377ce7c7bffbb1a6605a26479b',
  },
}

const works = (command: string) => spawnSync(command, ['version'], { stdio: 'ignore' }).status === 0

/** Beside the nearest node_modules, so a build cache keeps it; else the temp directory. */
const cacheDir = () => {
  for (let dir = process.cwd(); ; dir = path.dirname(dir)) {
    if (existsSync(path.join(dir, 'node_modules'))) return path.join(dir, 'node_modules', '.cache', 'fg-policy')
    if (path.dirname(dir) === dir) return path.join(tmpdir(), 'fg-policy')
  }
}

let found: Promise<string> | undefined

export const findOpa = (): Promise<string> =>
  (found ??= (async () => {
    if (process.env.OPA) return process.env.OPA
    if (works('opa')) return 'opa'

    const platform = `${process.platform}-${process.arch}`
    const release = RELEASES[platform]
    if (!release) {
      throw new Error(
        `There is no opa CLI, and no OPA release to fetch for ${platform}. Install it ` +
          '(https://www.openpolicyagent.org/docs/#1-download-opa), or set OPA to its path.'
      )
    }
    const file = path.join(cacheDir(), `opa-${OPA_VERSION}${process.platform === 'win32' ? '.exe' : ''}`)
    if (existsSync(file)) return file

    const url = `https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/${release.file}`
    console.error(`Fetching opa ${OPA_VERSION} for ${platform}…`)
    const response = await fetch(url)
    if (!response.ok) throw new Error(`Fetching ${url} failed: ${response.status}`)
    const bytes = Buffer.from(await response.arrayBuffer())
    const sha256 = createHash('sha256').update(bytes).digest('hex')
    if (sha256 !== release.sha256) {
      throw new Error(`${url} is not the opa ${OPA_VERSION} release: its SHA-256 is ${sha256}.`)
    }
    mkdirSync(path.dirname(file), { recursive: true })
    const partial = `${file}.${process.pid}`
    writeFileSync(partial, bytes)
    chmodSync(partial, 0o755)
    renameSync(partial, file)
    return file
  })())

/** opa has already said what went wrong; only its exit status is left to pass on. */
export class OpaFailed extends Error {
  readonly status: number

  constructor(status: number) {
    super(`opa exited with ${status}`)
    this.name = 'OpaFailed'
    this.status = status
  }
}

/** Run opa, its output going to this process's. */
export const opa = async (args: string[], cwd?: string) => {
  const result = spawnSync(await findOpa(), args, { stdio: 'inherit', cwd })
  if (result.error) throw result.error
  if (result.status !== 0) throw new OpaFailed(result.status ?? 1)
}
