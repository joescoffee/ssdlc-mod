import { expect, test } from 'claude-code/testing'

// Stand-ins for the engine beneath the plugin.
const engine = (on: any, links: Record<string, string> = {}, cwd = '/repo') => {
  let n = 0
  const spawned: { id: string; type: string }[] = []
  on('agent.list', () => ({ value: spawned.map(a => ({ ...a, description: '', status: 'running' })) }))
  on('ui.toast', () => ({ value: undefined }))
  on('fs.stat', (_: any, e: any) => ({ value: { kind: 'file', size: 1, mtimeMs: 0, isLink: e.path in links,
    realPath: e.path === '.' ? cwd : (links[e.path] ?? e.path) } }))
  on('agent.spawn', (_: any, e: any) => {
    const id = `agent-${++n}`
    spawned.push({ id, type: e.subagentType })
    return { agentId: id, model: 'm' }
  })
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

test('globs aimed at credential stores are refused, content searches are not', async ($, on) => {
  engine(on)
  const { agentId } = await $.agent.spawn({ prompt: 'review', subagentType: 'ssdlc:security-reviewer' })
  for (const [tool, args] of [
    ['Grep', { pattern: 'KEY', path: '/repo', glob: '.env*' }],
    ['Grep', { pattern: 'x', path: '/repo', glob: '**/*.pem' }],
    ['Glob', { pattern: '**/.ssh/**' }],
    ['Glob', { pattern: '**/id_ed25519' }],
  ] as const) {
    expect((await $.tool.call({ tool, ...args, agentId } as any)).deny).toMatch(/credential stores/)
  }
  for (const [tool, args] of [
    ['Grep', { pattern: '\\.env$|password', path: '/repo/src' }],
    ['Grep', { pattern: 'x', path: '/repo', glob: '*.env.example' }],
    ['Glob', { pattern: 'src/**/*.ts' }],
  ] as const) {
    expect((await $.tool.call({ tool, ...args, agentId } as any)).deny).toBe(undefined)
  }
})

test('a symlink in the repo that lands in a credential store is refused', async ($, on) => {
  engine(on, { '/repo/docs/notes.txt': '/root/.ssh/id_ed25519' })
  const { agentId } = await $.agent.spawn({ prompt: 'review', subagentType: 'ssdlc:security-reviewer' })
  const r = await $.tool.call({ tool: 'Read', file_path: '/repo/docs/notes.txt', agentId } as any)
  expect(r.deny).toMatch(/resolves to \/root\/\.ssh\/id_ed25519/)
  const ok = await $.tool.call({ tool: 'Read', file_path: '/repo/src/app.py', agentId } as any)
  expect(ok.deny).toBe(undefined)
})

test('review fixes: case, spellings, extra stores, broad searches, cwd', async ($, on) => {
  engine(on, {}, '/root')
  const { agentId } = await $.agent.spawn({ prompt: 'review', subagentType: 'ssdlc:security-reviewer' })
  const denied = async (tool: string, args: object) =>
    (await $.tool.call({ tool, ...args, agentId } as any)).deny
  for (const file_path of ['/Users/u/.SSH/id_rsa', '/repo/.ENV', '/srv/server.KEY', '//proc/self/environ', '/etc//shadow',
    '/var/run/secrets/kubernetes.io/serviceaccount/token', '/repo/.envrc', '/repo/.env.production.local',
    '/home/u/.claude.json', '/home/u/.claude/projects/x.jsonl', '/home/u/.zsh_history', '/k/id_ed25519_sk', '/a/b.jks']) {
    expect(await denied('Read', { file_path })).toMatch(/credential stores/)
  }
  for (const path of ['/', '/root', '/home/u', '/home/u/', '/etc', '/root/.config', 'C:\\']) {
    expect(await denied('Grep', { pattern: 'token', path })).toMatch(/recursively|credential/)
  }
  expect(await denied('Glob', { pattern: '**/.s[s]h/*' })).toMatch(/credential stores/)
  expect(await denied('Glob', { pattern: '**/.{ssh,aws}/*', path: '/repo' })).toMatch(/credential stores/)
})

test('review fixes: repo searches still work', async ($, on) => {
  engine(on, {}, '/work/repo')
  const { agentId } = await $.agent.spawn({ prompt: 'review', subagentType: 'ssdlc:security-reviewer' })
  for (const [tool, args] of [['Grep', { pattern: 'eval', path: '/work/repo/src' }], ['Grep', { pattern: 'eval' }],
    ['Glob', { pattern: 'src/**/*.py', path: '/work/repo' }], ['Read', { file_path: '/work/repo/config/settings.py' }]] as const) {
    expect((await $.tool.call({ tool, ...args, agentId } as any)).deny).toBe(undefined)
  }
})

test('a reviewer is recognised after a module reload, via the agent list', async ($, on) => {
  engine(on)
  const { agentId } = await $.agent.spawn({ prompt: 'review', subagentType: 'ssdlc:design-reviewer' })
  // A tool call from an agent id the module never saw spawn: looked up by type.
  const r = await $.tool.call({ tool: 'Bash', command: 'id', agentId } as any)
  expect(r.deny).toMatch(/read-only/)
})

test('a search without a path is judged by the working directory', async ($, on) => {
  on('ui.toast', () => ({ value: undefined }))
  on('agent.list', () => ({ value: [{ id: 'r1', type: 'ssdlc:security-reviewer', description: '', status: 'running' }] }))
  // The host resolves "." to the session's working directory; here that is /root.
  on('fs.stat', () => ({ value: { kind: 'dir', size: 0, mtimeMs: 0, isLink: false, realPath: '/root' } }))
  on('tool.call', () => ({ result: {} }))
  const r = await $.tool.call({ tool: 'Grep', pattern: 'token', agentId: 'r1' } as any)
  expect(r.deny).toMatch(/recursively/)
})
