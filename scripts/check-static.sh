#!/usr/bin/env bash
# Static gate: syntax + undefined-variable scan (catches ReferenceError before run)
set -uo pipefail
cd "$(dirname "$0")/.."
rc=0

if [ "$#" -gt 0 ]; then TARGETS=("$@"); else TARGETS=(scripts/*.mjs server.mjs); fi
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(scripts/run-batch.mjs)

for f in "${TARGETS[@]}"; do
  node --check "$f" || { echo "SYNTAX FAIL: $f"; rc=1; }
done

GLOBALS=(process console Buffer setInterval setTimeout clearInterval clearTimeout URL URLSearchParams
  fetch WebSocket AbortSignal AbortController __dirname module require global TextEncoder TextDecoder
  performance queueMicrotask structuredClone atob btoa crypto Blob FormData Headers Request Response)

args=(--no-config-lookup --rule '{"no-undef":"error"}' --parser-options '{"ecmaVersion":2023,"sourceType":"module"}' -f json)
for g in "${GLOBALS[@]}"; do args+=(--global "$g"); done

npx --yes eslint@9 "${args[@]}" "${TARGETS[@]}" > /tmp/undef.json 2>/dev/null
node -e '
const d = require("/tmp/undef.json");
const skip = new Set((process.env.SKIP || "").split(",").filter(Boolean));
let bad = 0;
for (const f of d) for (const m of f.messages) {
  if (m.ruleId !== "no-undef") continue;
  if (m.severity < 2) continue;
  bad++;
  console.log(`${f.filePath.split("/").pop()}:${m.line} ${m.message}`);
}
console.log(bad ? `UNDEF FAIL: ${bad}` : "UNDEF OK: 0");
process.exit(bad ? 1 : 0);
' 2>/dev/null || rc=1
# eslint exit code is non-zero on any finding; the node check above is the verdict
exit $rc
