// Main-session review mode (threat model CTARA-SSDLC-01/01B, OWASP LLM01:2026, ASI01, ASI02, ASI05).
//
// While reviewing an untrusted repository the main session reads attacker-controlled
// text and holds Bash, Write and the network: all three legs of the Rule of Two.
// Review mode bounds the third leg in code instead of in the prompt: only exact,
// non-executing command forms run, nothing leaves the machine, writes go to report
// paths only, and only this plugin's read-only reviewers may be spawned. It does not
// depend on the user's permission mode, so it still holds under bypass/acceptEdits.

const TOKEN = String.raw`(?:"[^"$\x60\\\n]*"|'[^'\n]*'|[^\s;&|$\x60<>()'"\\]+)`
const ARGS = String.raw`(?:\s+${TOKEN})*`
const REDIRECT = String.raw`(?:\s+>>?\s*${TOKEN})?`

const GIT_PREFIX = String.raw`env\s+GIT_CONFIG_NOSYSTEM=1\s+GIT_CONFIG_GLOBAL=/dev/null\s+git`
const GIT_REQUIRED = [
  '-c core.fsmonitor=false',
  '-c core.hooksPath=/dev/null',
  '-c core.attributesFile=/dev/null',
  '-c diff.external=',
]
const GIT_READ_SUBCOMMANDS = /\s(diff|log|show|ls-files|merge-base|rev-parse|status|cat-file)(\s|$)/
const GIT_PATCH_SUBCOMMANDS = /\s(diff|log|show)(\s|$)/

/** Exact command forms the main session may run in review mode. */
export const ALLOWED_BASH: { name: string; re: RegExp }[] = [
  { name: 'ssdlc scanner', re: new RegExp(String.raw`^python3\s+-I\s+${TOKEN}gate_scan\.py${ARGS}${REDIRECT}$`) },
  { name: 'hardened git (read-only subcommands)', re: new RegExp(String.raw`^${GIT_PREFIX}${ARGS}${REDIRECT}$`) },
  { name: 'osv-scanner', re: new RegExp(String.raw`^osv-scanner${ARGS}${REDIRECT}$`) },
  { name: 'npm audit --package-lock-only', re: new RegExp(String.raw`^npm\s+audit\s+--package-lock-only${ARGS}${REDIRECT}$`) },
  { name: 'pip-audit --disable-pip --no-deps', re: new RegExp(String.raw`^pip-audit\s+--disable-pip\s+--no-deps${ARGS}${REDIRECT}$`) },
  { name: 'tool versions', re: /^(osv-scanner|npm|pip-audit|python3|git)\s+--version$/ },
  { name: 'review copy (rsync without the repo\'s agent config)', re: new RegExp(String.raw`^rsync\s+-a${ARGS}$`) },
  { name: 'listing', re: new RegExp(String.raw`^(ls|wc|file|stat|pwd|mktemp|mkdir\s+-p)${ARGS}$`) },
]

/** Why a Bash command is refused in review mode, or undefined when it is allowed. */
export const bashVerdict = (command: string): string | undefined => {
  const cmd = command.trim()
  if (/[\n\r]/.test(cmd)) return 'multi-line commands are not allowed in review mode'
  const form = ALLOWED_BASH.find(f => f.re.test(cmd))
  if (form === undefined) {
    return `only these command forms run in review mode: ${ALLOWED_BASH.map(f => f.name).join('; ')}`
  }
  if (form.name.startsWith('hardened git')) {
    const missing = GIT_REQUIRED.filter(flag => !cmd.includes(flag))
    if (missing.length > 0) return `git needs the hardening flags ${missing.join(' ')} (see references/untrusted-repo.md §2)`
    if (!GIT_READ_SUBCOMMANDS.test(cmd)) return 'only read-only git subcommands run in review mode'
    if (GIT_PATCH_SUBCOMMANDS.test(cmd) && !(cmd.includes('--no-ext-diff') && cmd.includes('--no-textconv'))) {
      return 'git diff/log/show need --no-ext-diff --no-textconv in review mode'
    }
  }
  if (form.name.startsWith('review copy')) {
    for (const ex of ['.git', 'CLAUDE.md', 'AGENTS.md', '.claude']) {
      if (!cmd.includes(`--exclude ${ex}`) && !cmd.includes(`--exclude=${ex}`)) {
        return `the review copy must exclude ${ex} (references/untrusted-repo.md §5)`
      }
    }
  }
  return undefined
}

/** Report files the main session may write in review mode. */
export const REPORT_PATH = /([\/\\]docs[\/\\]reviews[\/\\][^\/\\]+\.md$|[\/\\](reviews?|reports?)[\/\\][^\/\\]+\.(md|json|txt)$|[-_](review|report)\.(md|json)$|^\/tmp\/claude-[^\/]+\/)/i

const NETWORK_TOOLS = new Set(['WebFetch', 'WebSearch'])
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit'])

/**
 * Why a main-session tool call is refused in review mode, or undefined when allowed.
 * `pluginName` scopes the plugin's own MCP tools and reviewer types.
 */
export const reviewModeVerdict = (
  tool: string,
  input: Record<string, unknown>,
  pluginName: string,
): string | undefined => {
  const str = (k: string) => (typeof input[k] === 'string' ? (input[k] as string) : '')
  if (tool === 'Bash') return bashVerdict(str('command'))
  if (NETWORK_TOOLS.has(tool)) return `${tool} is off in review mode: nothing leaves the machine while untrusted content is in context`
  if (WRITE_TOOLS.has(tool)) {
    const target = str('file_path') || str('notebook_path')
    return REPORT_PATH.test(target) ? undefined : `in review mode only report files may be written (docs/reviews/*.md, *-review.md, *-report.md); not ${target}`
  }
  if (tool === 'Agent' || tool === 'Task') {
    const type = str('subagent_type')
    return type.startsWith(`${pluginName}:`) && type.endsWith('reviewer')
      ? undefined
      : `in review mode only ${pluginName} read-only reviewers may be spawned (not ${type || 'general-purpose'})`
  }
  if (tool.startsWith('mcp__') && !tool.startsWith(`mcp__${pluginName}__`)) {
    return `MCP tools are off in review mode (${tool})`
  }
  return undefined
}

/** Only a person may switch review mode off: never the model, a plugin or a notification. */
export const isPersonOrigin = (origin: { kind: string } | undefined): boolean =>
  origin !== undefined && (origin.kind === 'composer' || origin.kind === 'bridge')
