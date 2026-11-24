const STORAGE_KEY = "jg-evidence";

export function readEvidence(storage = globalThis.localStorage) {
  try {
    const raw = storage.getItem(STORAGE_KEY);
    if (raw === null) return { items: [], error: null };
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return { items: [], error: "Saved evidence is not a valid list. Clear the damaged local data to continue." };
    }
    return {
      items: parsed.filter((item) => item && typeof item === "object" && item.result),
      error: null,
    };
  } catch (error) {
    return {
      items: [],
      error: error instanceof SyntaxError
        ? "Saved evidence contains invalid JSON. Clear the damaged local data to continue."
        : "Browser storage is unavailable. Check your browser privacy settings.",
    };
  }
}

export function saveEvidence(item, storage = globalThis.localStorage) {
  const current = readEvidence(storage);
  if (current.error) throw new Error(current.error);
  const next = [item, ...current.items].slice(0, 50);
  storage.setItem(STORAGE_KEY, JSON.stringify(next));
  return next;
}

export function removeEvidence(index, storage = globalThis.localStorage) {
  const current = readEvidence(storage);
  if (current.error) throw new Error(current.error);
  const next = current.items.filter((_, itemIndex) => itemIndex !== index);
  storage.setItem(STORAGE_KEY, JSON.stringify(next));
  return next;
}

export function clearEvidence(storage = globalThis.localStorage) {
  storage.removeItem(STORAGE_KEY);
}

export function exportEvidenceAsJson(storage = globalThis.localStorage) {
  const current = readEvidence(storage);
  if (current.error) throw new Error(current.error);
  return JSON.stringify(current.items, null, 2);
}

export function importEvidenceFromJson(jsonString, storage = globalThis.localStorage) {
  let parsed;
  try {
    parsed = JSON.parse(jsonString);
  } catch (e) {
    throw new Error("Uploaded file is not valid JSON.");
  }
  if (!Array.isArray(parsed)) {
    throw new Error("Imported JSON must be an array of evidence items.");
  }
  const valid = parsed.filter((item) => item && typeof item === "object" && item.result);
  if (valid.length === 0) {
    throw new Error("No valid evidence records found in the JSON file.");
  }
  const current = readEvidence(storage);
  const existing = current.error ? [] : current.items;
  const merged = [...valid, ...existing].slice(0, 50);
  storage.setItem(STORAGE_KEY, JSON.stringify(merged));
  return merged;
}
