import type { HistoryEntry, HistoryStore } from '../application/audit-history'

const DATABASE = 'fortiscope'
const STORE = 'audit-history'

const request = <T>(operation: IDBRequest<T>): Promise<T> => new Promise((resolve, reject) => {
  operation.onsuccess = () => resolve(operation.result)
  operation.onerror = () => reject(operation.error)
})

const openDatabase = (factory: IDBFactory): Promise<IDBDatabase> => new Promise((resolve, reject) => {
  const opening = factory.open(DATABASE, 1)
  opening.onupgradeneeded = () => {
    opening.result.createObjectStore(STORE, { keyPath: 'id' })
  }
  opening.onsuccess = () => resolve(opening.result)
  opening.onerror = () => reject(opening.error)
})

export const createIndexedDbHistoryStore = (factory: IDBFactory = indexedDB): HistoryStore => {
  const withStore = async <T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> => {
    const database = await openDatabase(factory)
    try {
      return await request(run(database.transaction(STORE, mode).objectStore(STORE)))
    } finally {
      database.close()
    }
  }
  return {
    list: () => withStore('readonly', (store) => store.getAll() as IDBRequest<HistoryEntry[]>),
    add: async (entry) => { await withStore('readwrite', (store) => store.put(entry)) },
    clear: async () => { await withStore('readwrite', (store) => store.clear()) },
  }
}
