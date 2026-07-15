// Small reusable form widgets shared by the CA and leaf forms
// (`ui/forms.ts`). Each widget owns its own DOM subtree and exposes a
// `getValue`/`root` pair — there is no shared reactive state here, `app.ts`
// just reads widgets' current values when the operator submits.

import { el } from "./dom.ts";

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
    getValue: () => rows.map((r) => r.value.trim()).filter((v) => v.length > 0),
    setValue,
  };
}

/** A repeatable list of `key=value` tag pairs, with an optional fixed/inherited prefix that cannot be removed. */
export function tagListInput(
  addLabel: string,
  removeLabel: string,
  fixed: [string, string][],
  initial: [string, string][] = [],
): { root: HTMLElement; getValue: () => [string, string][] } {
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
    const keyInput = el("input", { type: "text", value: key, placeholder: "key" });
    const valueInput = el("input", { type: "text", value, placeholder: "value" });
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

  const root = el("div", { class: "tag-list-widget" }, [list, addBtn]);
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
