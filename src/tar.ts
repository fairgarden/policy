import { gunzipSync, gzipSync } from 'node:zlib'

/** Far more than any policy: a bundle that unpacks to more is refused, not read. */
export const MAX_UNPACKED = 64 * 1024 * 1024

/**
 * Every file in a gzipped tarball, by name without a leading `/` or `./`:
 * what `opa build` writes. Directories and links are skipped.
 */
export const untar = (archive: Uint8Array): Map<string, Buffer> => {
  const tar = gunzipSync(archive, { maxOutputLength: MAX_UNPACKED })
  const field = (header: Buffer, start: number, end: number) =>
    header.subarray(start, end).toString('utf8').replace(/\0[\s\S]*$/, '').trim()
  const files = new Map<string, Buffer>()
  for (let offset = 0; offset + 512 <= tar.length; ) {
    const header = tar.subarray(offset, offset + 512)
    if (header.every((byte) => byte === 0)) break
    const size = parseInt(field(header, 124, 136) || '0', 8)
    const type = field(header, 156, 157)
    const prefix = field(header, 345, 500)
    const name = [prefix, field(header, 0, 100)].filter(Boolean).join('/').replace(/^\.?\//, '')
    const start = offset + 512
    if (type === '' || type === '0') files.set(name, tar.subarray(start, start + size))
    offset = start + Math.ceil(size / 512) * 512
  }
  return files
}

/** A gzipped ustar archive of these files, as `opa build` writes one. */
export const tar = (files: Map<string, Uint8Array>): Uint8Array => {
  const blocks: Buffer[] = []
  for (const [name, bytes] of files) {
    const header = Buffer.alloc(512)
    const full = `/${name}`
    // Names past 100 bytes go in the ustar prefix, split at a slash.
    const long = Buffer.byteLength(full) > 100
    const split = long ? full.lastIndexOf('/', 155) : -1
    if (long && (split <= 0 || Buffer.byteLength(full.slice(split + 1)) > 100 || Buffer.byteLength(full.slice(0, split)) > 155)) {
      throw new Error(`${name} is too long a path`)
    }
    header.write(split > 0 ? full.slice(split + 1) : full, 0, 100)
    if (split > 0) header.write(full.slice(0, split), 345, 155)
    header.write('0000644\0', 100)
    header.write('0000000\0', 108)
    header.write('0000000\0', 116)
    header.write(`${bytes.length.toString(8).padStart(11, '0')}\0`, 124)
    header.write('00000000000\0', 136)
    header.write('        ', 148)
    header.write('0', 156)
    header.write('ustar\u000000', 257)
    header.write(`${header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0')}\0 `, 148)
    blocks.push(header, Buffer.from(bytes), Buffer.alloc((512 - (bytes.length % 512)) % 512))
  }
  return gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)]))
}
