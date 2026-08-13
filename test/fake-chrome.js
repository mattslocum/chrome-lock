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

  /** Tab groups, keyed by group id. -1 is Chrome's TAB_GROUP_ID_NONE. */
  const groups = new Map();
  let nextGroupId = 1;

  function makeTab(windowId, { url, pinned = false, active = false, groupId = -1 }) {
    return { id: nextTabId++, windowId, url, pinned, active, groupId };
  }

  function findTab(tabId) {
    for (const win of windows.values()) {
      const tab = win.tabs.find((t) => t.id === tabId);
      if (tab) return tab;
    }
    return null;
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

      async create({ url, type = 'normal', left, top, width, height, state, focused: wantFocus }) {
        const id = nextWindowId++;
        const win = {
          id,
          type,
          left,
          top,
          width,
          height,
          state: state ?? 'normal',
          focused: false,
          incognito: false,
          tabs: [],
        };
        for (const [i, u] of [].concat(url ?? []).entries()) {
          win.tabs.push(makeTab(id, { url: u, active: i === 0 }));
        }
        windows.set(id, win);
        // Chrome focuses a newly created window, and focus is exclusive — the
        // engine relies on both when it restores the originally focused window.
        if (wantFocus !== false) focusWindow(id);
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
        const { focused, ...rest } = props;
        Object.assign(win, rest);
        if (focused === true) focusWindow(windowId);
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
        const tab = findTab(tabId);
        if (!tab) throw new Error(`No tab with id ${tabId}`);
        Object.assign(tab, props);
        // Pinning moves the tab to the front of the strip, and only one tab in a
        // window is active. Both matter to what the engine is asserted to restore.
        const win = windows.get(tab.windowId);
        if (props.pinned === true) {
          win.tabs.splice(win.tabs.indexOf(tab), 1);
          win.tabs.splice(win.tabs.filter((t) => t.pinned).length, 0, tab);
        }
        if (props.active === true) {
          for (const other of win.tabs) other.active = other === tab;
        }
        return structuredClone(tab);
      },

      async group({ tabIds, createProperties }) {
        const ids = [].concat(tabIds);
        const windowId = createProperties?.windowId;
        const id = nextGroupId++;
        groups.set(id, { id, windowId, title: '', color: 'grey', collapsed: false });
        for (const tabId of ids) {
          const tab = findTab(tabId);
          if (!tab) throw new Error(`No tab with id ${tabId}`);
          if (tab.pinned) throw new Error('Cannot group a pinned tab');
          tab.groupId = id;
        }
        return id;
      },
    },

    tabGroups: {
      async query({ windowId }) {
        return [...groups.values()]
          .filter((group) => windowId === undefined || group.windowId === windowId)
          .map((group) => structuredClone(group));
      },

      async update(groupId, props) {
        const group = groups.get(groupId);
        if (!group) throw new Error(`No group with id ${groupId}`);
        Object.assign(group, props);
        return structuredClone(group);
      },
    },
  };

  function focusWindow(windowId) {
    for (const win of windows.values()) win.focused = win.id === windowId;
  }

  return {
    chrome,

    /**
     * Seed a window as though the user had opened it. A tab spec may carry
     * `group: <name>`; every tab sharing a name in this window lands in one
     * group, created here with the given `groupSpecs` metadata.
     */
    openWindow({ tabs = [], left = 0, top = 0, width = 1440, height = 900, state = 'normal', incognito = false, focused = false, groupSpecs = {} } = {}) {
      const id = nextWindowId++;
      const win = { id, type: 'normal', left, top, width, height, state, incognito, focused, tabs: [] };
      const groupIdByName = new Map();

      for (const { group, ...spec } of tabs) {
        const tab = makeTab(id, spec);
        if (group != null) {
          if (!groupIdByName.has(group)) {
            const groupId = nextGroupId++;
            groups.set(groupId, {
              id: groupId,
              windowId: id,
              title: group,
              color: 'grey',
              collapsed: false,
              ...groupSpecs[group],
            });
            groupIdByName.set(group, groupId);
          }
          tab.groupId = groupIdByName.get(group);
        }
        win.tabs.push(tab);
      }

      windows.set(id, win);
      if (focused) focusWindow(id);
      return win;
    },

    listGroups() {
      return [...groups.values()].map((group) => structuredClone(group));
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
