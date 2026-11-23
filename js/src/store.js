// Persistent state (Node): one file per key in a directory.
import fs from 'node:fs/promises'
import path from 'node:path'

export function createStore (dir) {
  return {
    async read (name) {
      try {
        return await fs.readFile(path.join(dir, name), 'utf8')
      } catch (err) {
        if (err.code === 'ENOENT') return null
        throw err
      }
    },
    async write (name, data, { secret = false } = {}) {
      await fs.mkdir(dir, { recursive: true })
      const file = path.join(dir, name)
      await fs.writeFile(file + '.tmp', data, { mode: secret ? 0o600 : 0o644 })
      await fs.rename(file + '.tmp', file)
    }
  }
}
