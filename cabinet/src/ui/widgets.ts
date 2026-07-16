// Small reusable form widgets shared by the CA and leaf forms
// (`ui/forms.ts`). Each widget owns its own DOM subtree and exposes a
// `getValue`/`root` pair — there is no shared reactive state here, `app.ts`
// just reads widgets' current values when the operator submits.

import { el } from "./dom.ts";

/**
 * Pure filtering shared by every free-text list widget's `getValue`: trim
 * each entry, drop empties. Factored out so {@link suggestingStringListInput}
 * — a native `<input list>` combobox that can't be driven headlessly in
 * `node:test` without a DOM — still has a unit-tested core; the widget itself
 * is exercised by hand like the rest of `ui/*`.
 */
export function filterStringListValues(values: string[]): string[] {
  return values.map((v) => v.trim()).filter((v) => v.length > 0);
}

/** A repeatable list of free-text strings (host_binding, user_binding, …). */
export function stringListInput(
  addLabel: string,
  removeLabel: string,
  initial: string[] = [],
): { root: HTMLElement; getValue: () => string[]; setValue: (values: string[]) => void } {
  const list = el("div", { class: "string-list" });
  let rows: HTMLInputElement[] = [];

  function addRow(value = ""): void {
    const input = el("input", { type: "text", value });
    const removeBtn = el("button", { type: "button", class: "btn-remove" }, [removeLabel]);
    const row = el("div", { class: "string-list-row" }, [input, removeBtn]);
    removeBtn.addEventListener("click", () => {
      row.remove();
      rows.splice(rows.indexOf(input), 1);
    });
    rows.push(input);
    list.append(row);
  }

  function setValue(values: string[]): void {
    list.replaceChildren();
    rows = [];
    for (const value of values.length > 0 ? values : [""]) addRow(value);
  }

  setValue(initial);

  const addBtn = el("button", { type: "button", class: "btn-add" }, [addLabel]);
  addBtn.addEventListener("click", () => addRow());

  const root = el("div", { class: "string-list-widget" }, [list, addBtn]);
  return {
    root,
    getValue: () => filterStringListValues(rows.map((r) => r.value)),
    setValue,
  };
}

let suggestingListInstanceCounter = 0;

/**
 * Like {@link stringListInput}, but each row is a native `<input list=…>`
 * combobox wired to a shared `<datalist>` of `suggestions` — CSP-safe (no
 * external resources, `default-src 'self'` in `public/index.html`), and free
 * text is always preserved: the datalist only offers completions, it never
 * constrains what `getValue` returns (spec `issuer-cabinet` — "оператор МОЖЕТ
 * ввести значение, которого в инвентаре нет"). The datalist id is derived
 * from a module-level counter, not `Math.random()`/`Date.now()`, so it stays
 * stable and never collides across the several instances a single render can
 * create (host binding + user binding on the same form).
 */
export function suggestingStringListInput(
  addLabel: string,
  removeLabel: string,
  suggestions: string[] = [],
  initial: string[] = [],
): { root: HTMLElement; getValue: () => string[]; setValue: (values: string[]) => void } {
  suggestingListInstanceCounter += 1;
  const datalistId = `suggesting-string-list-${suggestingListInstanceCounter}`;
  const datalist = el(
    "datalist",
    { id: datalistId },
    suggestions.map((s) => el("option", { value: s })),
  );

  const list = el("div", { class: "string-list" });
  let rows: HTMLInputElement[] = [];

  function addRow(value = ""): void {
    const input = el("input", { type: "text", value, list: datalistId });
    const removeBtn = el("button", { type: "button", class: "btn-remove" }, [removeLabel]);
    const row = el("div", { class: "string-list-row" }, [input, removeBtn]);
    removeBtn.addEventListener("click", () => {
      row.remove();
      rows.splice(rows.indexOf(input), 1);
    });
    rows.push(input);
    list.append(row);
  }

  function setValue(values: string[]): void {
    list.replaceChildren();
    rows = [];
    for (const value of values.length > 0 ? values : [""]) addRow(value);
  }

  setValue(initial);

  const addBtn = el("button", { type: "button", class: "btn-add" }, [addLabel]);
  addBtn.addEventListener("click", () => addRow());

  const root = el("div", { class: "string-list-widget suggesting-string-list-widget" }, [
    datalist,
    list,
    addBtn,
  ]);
  return {
    root,
    getValue: () => filterStringListValues(rows.map((r) => r.value)),
    setValue,
  };
}

export interface HostEntry {
  id: string;
  label?: string;
}

/** A repeatable list of `{id, label?}` device entries, for the inventory constructor's device editor. */
export function hostListInput(
  addLabel: string,
  removeLabel: string,
  idPlaceholder: string,
  labelPlaceholder: string,
  initial: HostEntry[] = [],
): { root: HTMLElement; getValue: () => HostEntry[] } {
  const list = el("div", { class: "host-list" });
  const rows: { id: HTMLInputElement; label: HTMLInputElement }[] = [];

  function addRow(id = "", label = ""): void {
    const idInput = el("input", { type: "text", value: id, placeholder: idPlaceholder });
    const labelInput = el("input", { type: "text", value: label, placeholder: labelPlaceholder });
    const removeBtn = el("button", { type: "button", class: "btn-remove" }, [removeLabel]);
    const row = el("div", { class: "host-list-row" }, [idInput, labelInput, removeBtn]);
    removeBtn.addEventListener("click", () => {
      row.remove();
      const idx = rows.findIndex((r) => r.id === idInput);
      if (idx >= 0) rows.splice(idx, 1);
    });
    rows.push({ id: idInput, label: labelInput });
    list.append(row);
  }

  for (const entry of initial) addRow(entry.id, entry.label ?? "");
  if (initial.length === 0) addRow();

  const addBtn = el("button", { type: "button", class: "btn-add" }, [addLabel]);
  addBtn.addEventListener("click", () => addRow());

  const root = el("div", { class: "host-list-widget" }, [list, addBtn]);
  return {
    root,
    getValue: () =>
      rows
        .map(({ id, label }) => ({ id: id.value.trim(), label: label.value.trim() || undefined }))
        .filter((h) => h.id.length > 0),
  };
}

let tagListInstanceCounter = 0;

/**
 * A repeatable list of `key=value` tag pairs, with an optional
 * fixed/inherited prefix that cannot be removed. `keySuggestions`/
 * `valueSuggestions` (from the loaded inventory, when present) feed two
 * `<datalist>`s — a polish-level completion aid (spec design §1: "мелочь,
 * необязательный полировочный штрих"), not a constraint; free `key=value`
 * entry always works regardless of what the inventory contains.
 */
export function tagListInput(
  addLabel: string,
  removeLabel: string,
  fixed: [string, string][],
  initial: [string, string][] = [],
  keySuggestions: string[] = [],
  valueSuggestions: string[] = [],
): { root: HTMLElement; getValue: () => [string, string][] } {
  tagListInstanceCounter += 1;
  const keyListId = `tag-list-keys-${tagListInstanceCounter}`;
  const valueListId = `tag-list-values-${tagListInstanceCounter}`;
  const keyDatalist = el(
    "datalist",
    { id: keyListId },
    keySuggestions.map((k) => el("option", { value: k })),
  );
  const valueDatalist = el(
    "datalist",
    { id: valueListId },
    valueSuggestions.map((v) => el("option", { value: v })),
  );

  const list = el("div", { class: "tag-list" });
  const rows: { key: HTMLInputElement; value: HTMLInputElement }[] = [];

  for (const [key, value] of fixed) {
    const row = el("div", { class: "tag-list-row tag-list-row-fixed" }, [
      el("span", { class: "tag-fixed-key" }, [key]),
      el("span", {}, ["="]),
      el("span", { class: "tag-fixed-value" }, [value]),
    ]);
    list.append(row);
  }

  function addRow(key = "", value = ""): void {
    const keyInput = el("input", { type: "text", value: key, placeholder: "key", list: keyListId });
    const valueInput = el("input", {
      type: "text",
      value,
      placeholder: "value",
      list: valueListId,
    });
    const removeBtn = el("button", { type: "button", class: "btn-remove" }, [removeLabel]);
    const row = el("div", { class: "tag-list-row" }, [keyInput, valueInput, removeBtn]);
    removeBtn.addEventListener("click", () => {
      row.remove();
      const idx = rows.findIndex((r) => r.key === keyInput);
      if (idx >= 0) rows.splice(idx, 1);
    });
    rows.push({ key: keyInput, value: valueInput });
    list.append(row);
  }

  for (const [key, value] of initial) addRow(key, value);

  const addBtn = el("button", { type: "button", class: "btn-add" }, [addLabel]);
  addBtn.addEventListener("click", () => addRow());

  const root = el("div", { class: "tag-list-widget" }, [keyDatalist, valueDatalist, list, addBtn]);
  return {
    root,
    getValue: () => [
      ...fixed,
      ...rows
        .map(({ key, value }) => [key.value.trim(), value.value.trim()] as [string, string])
        .filter(([key]) => key.length > 0),
    ],
  };
}

/** A checkbox group for role selection, constrained to `options`. */
export function roleCheckboxGroup(
  options: string[],
  selected: string[] = [],
): { root: HTMLElement; getValue: () => string[]; setValue: (roles: string[]) => void } {
  const boxes: { input: HTMLInputElement; role: string }[] = [];
  const root = el(
    "div",
    { class: "role-checkbox-group" },
    options.map((role) => {
      const input = el("input", {
        type: "checkbox",
        value: role,
        checked: selected.includes(role) ? "checked" : undefined,
      });
      boxes.push({ input, role });
      return el("label", { class: "role-checkbox" }, [input, role]);
    }),
  );
  return {
    root,
    getValue: () => boxes.filter((b) => b.input.checked).map((b) => b.role),
    setValue: (roles) => {
      for (const box of boxes) box.input.checked = roles.includes(box.role);
    },
  };
}

/** Convert a `datetime-local` input's value to Unix seconds; `undefined` if empty/invalid. */
export function datetimeLocalToUnix(value: string): number | undefined {
  if (!value) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : Math.floor(ms / 1000);
}

/** Convert Unix seconds to a `datetime-local` input value, UTC. */
export function unixToDatetimeLocal(seconds: number): string {
  return new Date(seconds * 1000).toISOString().slice(0, 16);
}
