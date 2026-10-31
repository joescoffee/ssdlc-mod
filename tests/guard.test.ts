import { expect, test } from 'claude-code/testing'

// Stand-ins for the engine beneath the plugin.
const engine = (on: any) => {
  let n = 0
  on('agent.spawn', () => ({ agentId: `agent-${++n}`, model: 'm' }))
  on('tool.call', () => ({ result: {} }))
}

test('a reviewer agent cannot write or run commands', async ($, on) => {
  engine(on)
  const { agentId } = await $.agent.spawn({ prompt: 'review', subagentType: 'ssdlc:security-reviewer' })
  const bash = await $.tool.call({ tool: 'Bash', command: 'rm -rf /', agentId } as any)
  expect(bash.deny).toMatch(/read-only/)
  const write = await $.tool.call({ tool: 'Write', file_path: '/x', content: '', agentId } as any)
  expect(write.deny).toMatch(/read-only/)
})

test('a reviewer agent can still read', async ($, on) => {
  engine(on)
  const { agentId } = await $.agent.spawn({ prompt: 'review', subagentType: 'ssdlc:design-reviewer' })
  const read = await $.tool.call({ tool: 'Read', file_path: '/repo/a.py', agentId } as any)
  expect(read.deny).toBe(undefined)
})

test('other agents and the main loop are untouched', async ($, on) => {
  engine(on)
  const { agentId } = await $.agent.spawn({ prompt: 'x', subagentType: 'general-purpose' })
  expect((await $.tool.call({ tool: 'Bash', command: 'ls', agentId } as any)).deny).toBe(undefined)
  expect((await $.tool.call({ tool: 'Bash', command: 'ls' } as any)).deny).toBe(undefined)
})
