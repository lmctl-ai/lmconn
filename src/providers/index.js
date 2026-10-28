// Provider registry: the one table that names every LLM provider lmconn can
// call. kind 'api' = OpenAI-compatible HTTPS; kind 'cli' = an agent CLI that
// answers one prompt on stdout. Keys resolve from the SQLite store first,
// then the environment variable named here. Values are never printed.

import { getCred } from '../creds.js';

export const providers = {
  deepseek: {
    kind: 'api',
    baseUrl: 'https://api.deepseek.com',
    keyEnv: 'DEEPSEEK_API_KEY',
    defaultModel: 'deepseek-flash',
    models: ['deepseek-flash', 'deepseek-chat', 'deepseek-v4-pro'],
  },
  openrouter: {
    kind: 'api',
    baseUrl: 'https://openrouter.ai/api/v1',
    keyEnv: 'OPENROUTER_API_KEY',
    defaultModel: 'liquid/lfm-2.5-2.6b:free',
  },
  'ollama-cloud': {
    kind: 'api',
    baseUrl: 'https://ollama.com/v1',
    keyEnv: 'OLLAMA_API_KEY',
    defaultModel: 'gpt-oss:20b-cloud',
  },
  claude: { kind: 'cli', cmd: ['claude', '-p'], timeoutMs: 180000 },
  codex: { kind: 'cli', cmd: ['codex', 'exec', '--skip-git-repo-check'], timeoutMs: 240000 },
  agy: { kind: 'cli', cmd: ['agy', '-p'], timeoutMs: 180000 },
  kimi: { kind: 'cli', cmd: ['kimi', '-p'], timeoutMs: 180000 },
};

export function providerNames() {
  return Object.keys(providers);
}

// Returns { value, source } where source is 'store', 'env:<NAME>', 'none'
// (provider needs no key) or 'missing'. The value is never logged.
export function resolveKey(name) {
  const p = providers[name];
  if (!p) throw new Error(`unknown provider: ${name}`);
  if (!p.keyEnv) return { value: null, source: 'none' };
  const stored = getCred(name, 'api_key');
  if (stored) return { value: stored, source: 'store' };
  const fromEnv = process.env[p.keyEnv];
  if (fromEnv) return { value: fromEnv, source: `env:${p.keyEnv}` };
  return { value: null, source: 'missing' };
}
