/** A guard event: a reviewer agent did something it should not (OWASP ASI02/ASI03, LLM01:2026). */
export type GuardAlert = {
  /** ISO time the call was refused. */
  at: string
  agentId: string
  /** tripwire: credential-store access or a forbidden tool — strong sign of prompt injection. warn: an over-broad search. */
  level: 'tripwire' | 'warn'
  tool: string
  detail: string
  /** True once the main session has been told. */
  delivered: boolean
}

declare module 'claude-code' {
  interface PluginState {
    ssdlc: {
      /** Main-session review mode: only exact, non-executing command forms are allowed. */
      reviewMode: boolean
      alerts: GuardAlert[]
    }
  }
}
