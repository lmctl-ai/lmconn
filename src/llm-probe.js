import { performance } from 'node:perf_hooks';
import { providers } from './providers/index.js';
import { chatCli } from './providers/cli.js';

export async function probe(names = Object.keys(providers)) {
  const results = [];
  for (const name of names) {
    const started = performance.now();
    const provider = Object.hasOwn(providers, name) ? providers[name] : null;
    const entry = { provider: name, kind: provider?.kind ?? null, ok: false, latencyMs: 0, reply: '', error: null };
    try {
      if (!provider) throw new Error(`unknown provider: ${name}`);
      const options = { prompt: 'Reply with exactly: pong' };
      let result;
      if (provider.kind === 'api') {
        let chatApi;
        try {
          ({ chatApi } = await import('./providers/api.js'));
        } catch (error) {
          throw new Error(`API adapter unavailable: ${error.message}`);
        }
        result = await chatApi(name, { ...options, maxTokens: 200 });
      } else if (provider.kind === 'cli') {
        result = await chatCli(name, options);
      } else {
        throw new Error(`unsupported provider kind: ${provider.kind}`);
      }
      entry.reply = result.text.slice(0, 80);
      entry.ok = true;
    } catch (error) {
      entry.error = error instanceof Error ? error.message : String(error);
    }
    entry.latencyMs = Math.round(performance.now() - started);
    results.push(entry);
  }
  return results;
}
