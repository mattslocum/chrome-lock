/**
 * A minimal in-memory stand-in for the slice of the Chrome extension API that
 * the lock engine uses: storage.local, storage.managed, windows and tabs.
 *
 * It models windows and tabs as real objects with ids, so a test can assert on
 * what is actually open rather than on which calls were made. Listeners are not
 * simulated — the engine's protection-mode handlers are exported functions and
 * the tests call them directly, which is also how service_worker.js invokes them.
 */

export function createFakeChrome() {
  const local = new Map();
  const managed = new Map();
  const windows = new Map();
  let nextWindowId = 1;
  let nextTabId = 1;

  function makeTab(windowId, { url, pinned = false, active = false }) {
    return { id: nextTabId++, windowId, url, pinned, active };
  }

  const storageArea = (map) => ({
    async get(keys) {
      const wanted = keys === null || keys === undefined ? [...map.keys()] : [].concat(keys);
      const out = {};
      for (const key of wanted) {
        if (map.has(key)) out[key] = structuredClone(map.get(key));
      }
      return out;
    },
    async set(items) {
      for (const [key, value] of Object.entries(items)) map.set(key, structuredClone(value));
    },
    async remove(keys) {
      for (const key of [].concat(keys)) map.delete(key);
    },
  });

  const chrome = {
    runtime: {
      id: 'fake-extension-id',
      getURL: (path) => `chrome-extension://fake-extension-id/${path}`,
    },

    storage: {
      local: storageArea(local),
      // Managed storage throws when no policy is configured, which is the normal
      // case on an unmanaged profile — getEscrowBundle has to tolerate it.
      managed: {
        async get(keys) {
          if (managed.size === 0) throw new Error('Managed storage is not available');
          return storageArea(managed).get(keys);
        },
      },
    },

    windows: {
      WINDOW_ID_NONE: -1,

      async create({ url, type = 'normal', left, top, width, height, state, focused }) {
        const id = nextWindowId++;
        const win = {
          id,
          type,
          left,
          top,
          width,
          height,
          state: state ?? 'normal',
          focused: focused === true,
          incognito: false,
          tabs: [],
        };
        for (const [i, u] of [].concat(url ?? []).entries()) {
          win.tabs.push(makeTab(id, { url: u, active: i === 0 }));
        }
        windows.set(id, win);
        return structuredClone(win);
      },

      async getAll({ populate = false, windowTypes } = {}) {
        return [...windows.values()]
          .filter((win) => !windowTypes || windowTypes.includes(win.type))
          .map((win) => {
            const copy = structuredClone(win);
            if (!populate) delete copy.tabs;
            return copy;
          });
      },

      async remove(windowId) {
        if (!windows.has(windowId)) throw new Error(`No window with id ${windowId}`);
        windows.delete(windowId);
      },

      async update(windowId, props) {
        const win = windows.get(windowId);
        if (!win) throw new Error(`No window with id ${windowId}`);
        Object.assign(win, props);
        return structuredClone(win);
      },
    },

    tabs: {
      async remove(tabId) {
        for (const win of windows.values()) {
          const index = win.tabs.findIndex((tab) => tab.id === tabId);
          if (index !== -1) {
            win.tabs.splice(index, 1);
            return;
          }
        }
        throw new Error(`No tab with id ${tabId}`);
      },

      async update(tabId, props) {
        for (const win of windows.values()) {
          const tab = win.tabs.find((t) => t.id === tabId);
          if (tab) {
            Object.assign(tab, props);
            return structuredClone(tab);
          }
        }
        throw new Error(`No tab with id ${tabId}`);
      },
    },
  };

  return {
    chrome,

    /** Seed a window as though the user had opened it. */
    openWindow({ tabs = [], left = 0, top = 0, width = 1440, height = 900, state = 'normal', incognito = false } = {}) {
      const id = nextWindowId++;
      const win = { id, type: 'normal', left, top, width, height, state, incognito, focused: false, tabs: [] };
      for (const spec of tabs) win.tabs.push(makeTab(id, spec));
      windows.set(id, win);
      return win;
    },

    /** Seed an escrow bundle into managed storage. */
    setManaged(key, value) {
      managed.set(key, value);
    },

    /** Everything the extension has written to disk, as it would be persisted. */
    dumpStorage() {
      return Object.fromEntries([...local.entries()].map(([k, v]) => [k, structuredClone(v)]));
    },

    /** Replace what is on disk — used to simulate a disable/re-enable cycle. */
    loadStorage(dump) {
      local.clear();
      for (const [key, value] of Object.entries(dump)) local.set(key, structuredClone(value));
    },

    listWindows() {
      return [...windows.values()].map((win) => structuredClone(win));
    },

    closeAllWindows() {
      windows.clear();
    },
  };
}
