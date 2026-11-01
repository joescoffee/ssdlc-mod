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

test('a reviewer agent can hand its report back', async ($, on) => {
  engine(on)
  const { agentId } = await $.agent.spawn({ prompt: 'review', subagentType: 'ssdlc:security-reviewer' })
  const back = await $.tool.call({ tool: 'SubagentHandback', agentId } as any)
  expect(back.deny).toBe(undefined)
})

test('other agents and the main loop are untouched', async ($, on) => {
  engine(on)
  const { agentId } = await $.agent.spawn({ prompt: 'x', subagentType: 'general-purpose' })
  expect((await $.tool.call({ tool: 'Bash', command: 'ls', agentId } as any)).deny).toBe(undefined)
  expect((await $.tool.call({ tool: 'Bash', command: 'ls' } as any)).deny).toBe(undefined)
})

test('a reviewer agent cannot read credential stores', async ($, on) => {
  engine(on)
  const { agentId } = await $.agent.spawn({ prompt: 'review', subagentType: 'ssdlc:security-reviewer' })
  for (const file_path of ['/root/.ssh/id_rsa', '/home/u/.aws/credentials', '/repo/.env', '/repo/.env.production',
    '/root/.claude/.credentials.json', '/home/u/.netrc', '/repo/certs/server.key', '/proc/self/environ']) {
    const r = await $.tool.call({ tool: 'Read', file_path, agentId } as any)
    expect(r.deny).toMatch(/credential stores/)
  }
  const g = await $.tool.call({ tool: 'Grep', pattern: 'AKIA', path: '/home/u/.aws', agentId } as any)
  expect(g.deny).toMatch(/credential stores/)
})

test('ordinary source files that merely look similar stay readable', async ($, on) => {
  engine(on)
  const { agentId } = await $.agent.spawn({ prompt: 'review', subagentType: 'ssdlc:security-reviewer' })
  for (const file_path of ['/repo/src/env.ts', '/repo/docs/ssh.md', '/repo/.env.example', '/repo/.env.sample', '/repo/keys.py', '/repo/environment.py']) {
    const r = await $.tool.call({ tool: 'Read', file_path, agentId } as any)
    expect(r.deny).toBe(undefined)
  }
})

test('the main loop may still read anything the user allows', async ($, on) => {
  engine(on)
  const r = await $.tool.call({ tool: 'Read', file_path: '/repo/.env' } as any)
  expect(r.deny).toBe(undefined)
})
