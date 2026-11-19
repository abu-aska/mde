// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface DigestRecord {
  readonly id: string;
  readonly sha256: string;
}

// Keep sibling comment intact during function splices.
export function formatHeader(rec: DigestRecord): string {
  return `${rec.id}:${rec.sha256}`;
}

export async function loadPlugin(specifier: string): Promise<unknown> {
  return import(specifier);
}
