export function normalizeCommand(cmd: string): string {
  if (!cmd) return "";
  return cmd
    .toLowerCase()
    .replace(/['"]/g, "")       // strip quotes
    .replace(/\s+/g, " ")       // collapse whitespace
    .trim();
}
