// Browser: no filesystem; state lives for the page's lifetime.
export function createStore () {
  const m = new Map()
  return {
    async read (name) { return m.get(name) ?? null },
    async write (name, data) { m.set(name, data) }
  }
}
