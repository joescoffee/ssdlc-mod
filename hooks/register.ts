import type { Register } from 'claude-code'

// Defense in depth for the reviewer agents (OWASP ASI02/ASI03, LLM02:2026).
// Their frontmatter already limits them to Read/Grep/Glob; this guard
//  1. refuses any other tool, should a host or a future edit widen that list;
//  2. refuses reads of credential stores, so a prompt-injected review target
//     ("see ~/.aws/credentials for context") cannot pull secrets into a report.
// Agent ids are kept per module load: after a reload the frontmatter remains
// the control for reviewers already running.

// SubagentHandback is how a subagent returns its report to the caller: it
// writes nothing, and refusing it silently swallows every review.
const READ_ONLY = new Set(['Read', 'Grep', 'Glob', 'SubagentHandback'])

// Credential and secret stores a code review never needs.
export const SENSITIVE_PATH =
  /(^|[\/\\])(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.azure|\.config[\/\\]gcloud|\.config[\/\\]gh)([\/\\]|$)|(^|[\/\\])\.claude[\/\\]\.credentials\.json$|(^|[\/\\])\.(netrc|npmrc|pypirc|git-credentials|pgpass)$|(^|[\/\\])\.env(?!\.(example|sample|template|dist)$)(\.[\w-]+)?$|(^|[\/\\])id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|\.(pem|key|p12|pfx|kdbx)$|^\/proc\/|^\/etc\/(shadow|gshadow|sudoers)/

const reviewers = new Set<string>()

export const isReviewerType = (type: string | undefined): boolean =>
  type !== undefined && /^ssdlc:.*reviewer$/.test(type)

// Glob strings that aim at credential stores, e.g. `.env*`, `**` + `/.ssh/**`, `*.pem`.
export const SENSITIVE_GLOB =
  /(^|[\/\\*{,])\.env(?!\.(example|sample|template|dist)\b)|\.(ssh|aws|gnupg|kube|netrc|npmrc|pypirc|git-credentials|pgpass)\b|\.credentials\.json|id_(rsa|dsa|ecdsa|ed25519)|\.(pem|key|p12|pfx|kdbx)\b/

/**
 * The path-like arguments of each read-only tool. Grep's `pattern` searches
 * file contents, so it is not a path and is not checked.
 */
export const touchedPaths = (tool: string, e: Record<string, unknown>): { paths: string[]; globs: string[] } => {
  const str = (k: string) => (typeof e[k] === 'string' ? [e[k] as string] : [])
  if (tool === 'Read') return { paths: str('file_path'), globs: [] }
  if (tool === 'Grep') return { paths: str('path'), globs: str('glob') }
  if (tool === 'Glob') return { paths: str('path'), globs: str('pattern') }
  return { paths: [], globs: [] }
}

export const sensitiveTarget = (tool: string, e: Record<string, unknown>): string | undefined => {
  const { paths, globs } = touchedPaths(tool, e)
  return paths.find(p => SENSITIVE_PATH.test(p)) ?? globs.find(g => SENSITIVE_GLOB.test(g) || SENSITIVE_PATH.test(g))
}

export const register: Register = on => {
  on('agent.spawn', async ($, e, next) => {
    const started = await next(e)
    if (isReviewerType(e.subagentType) && started.agentId !== undefined) {
      reviewers.add(started.agentId)
    }
    return started
  })

  on('tool.call', ($, e, next) => {
    if (e.agentId === undefined || !reviewers.has(e.agentId)) return next(e)
    if (!READ_ONLY.has(e.tool)) {
      return { deny: `${$.plugin.name}: reviewer agents are read-only (${e.tool} refused).` }
    }
    const hit = sensitiveTarget(e.tool, e as unknown as Record<string, unknown>)
    if (hit !== undefined) {
      return {
        deny: `${$.plugin.name}: reviewers may not read credential stores (${hit}). Report the reference as a finding instead.`,
      }
    }
    return next(e)
  }).catch(($, e, next) =>
    next.called ? next(e) : { deny: `${$.plugin.name}: read-only guard failed.` },
  )
}
