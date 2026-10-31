import type { Register } from 'claude-code'

// Defense in depth for the reviewer agents. Their frontmatter already limits
// them to Read/Grep/Glob; this guard refuses anything else should a host or a
// future edit widen that list. Agent ids are kept per module load: after a
// reload the frontmatter remains the control for reviewers already running.
const READ_ONLY = new Set(['Read', 'Grep', 'Glob'])
const reviewers = new Set<string>()

export const isReviewerType = (type: string | undefined): boolean =>
  type !== undefined && /^ssdlc:.*reviewer$/.test(type)

export const register: Register = on => {
  on('agent.spawn', async ($, e, next) => {
    const started = await next(e)
    if (isReviewerType(e.subagentType) && started.agentId !== undefined) {
      reviewers.add(started.agentId)
    }
    return started
  })

  on('tool.call', ($, e, next) => {
    if (e.agentId !== undefined && reviewers.has(e.agentId) && !READ_ONLY.has(e.tool)) {
      return { deny: `${$.plugin.name}: reviewer agents are read-only (${e.tool} refused).` }
    }
    return next(e)
  }).catch(($, e, next) =>
    next.called ? next(e) : { deny: `${$.plugin.name}: read-only guard failed.` },
  )
}
