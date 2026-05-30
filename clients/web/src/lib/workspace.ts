import * as path from "path";

// Single source of truth for the engagement-name policy. Must stay in sync with
// the Go launcher (clients/launcher/internal/engagement/picker.go) since `name`
// doubles as an on-disk workspace directory shared by both sides.
export const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;

// Path-traversal containment: refuse any `name` whose resolved directory escapes
// `workspace`, so a poisoned DB row (e.g. "../../etc" from the CLI auto-import
// path) cannot be read. Checked on the resolved absolute path, not the raw input.
export function resolveEngagementDir(name: string, workspace: string): string {
  const root = path.resolve(workspace);
  const dir = path.resolve(root, name);
  if (dir !== root && !dir.startsWith(root + path.sep)) {
    throw new Error("invalid engagement path");
  }
  return dir;
}
