import { providers, resolveKey } from './index.js';

function error(code, message, status) {
  return Object.assign(new Error(message), { code, ...(status ? { status } : {}) });
}

export async function chatApi(name, { model, prompt, system, maxTokens = 256, timeoutMs = 120000 }) {
  const provider = Object.hasOwn(providers, name) && providers[name];
  if (!provider || provider.kind !== 'api') throw error('USAGE', `unknown API provider: ${name}`);
  if (typeof prompt !== 'string' || (system !== undefined && typeof system !== 'string')) {
    throw error('USAGE', 'prompt and system must be strings');
  }
  if (!Number.isSafeInteger(maxTokens) || maxTokens < 1 || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw error('USAGE', 'maxTokens and timeoutMs must be positive integers');
  }
  const { value, source } = resolveKey(name);
  if (source === 'missing') throw error('MISSING_KEY', `no API key configured for ${name}`);
  const redact = (text) => {
    const clean = value ? String(text).split(value).join('[REDACTED]') : String(text);
    return clean.replace(/\bBearer\s+[^\s"'<>;,]+/gi, 'Bearer [REDACTED]');
  };
  const selectedModel = model ?? provider.defaultModel;
  const start = performance.now();
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    const response = await fetch(`${provider.baseUrl.replace(/\/+$/, '')}/chat/completions`, {
      method: 'POST', signal,
      headers: { 'Content-Type': 'application/json', ...(value ? { Authorization: `Bearer ${value}` } : {}) },
      body: JSON.stringify({ model: selectedModel, max_tokens: maxTokens, messages: [
        ...(system !== undefined ? [{ role: 'system', content: system }] : []),
        { role: 'user', content: prompt },
      ] }),
    });
    if (!response.ok) {
      const excerpt = redact(await response.text()).replace(/\s+/g, ' ').slice(0, 300);
      throw error('HTTP_ERROR', `HTTP ${response.status}${excerpt ? `: ${excerpt}` : ''}`, response.status);
    }
    // Redact the entire payload before selecting output fields, including echoed credentials.
    const data = JSON.parse(redact(await response.text()));
    const text = data?.choices?.[0]?.message?.content;
    if (typeof text !== 'string') throw error('INVALID_RESPONSE', 'provider response has no assistant text');
    return { text, model: data.model ?? selectedModel, usage: data.usage ?? null,
      latencyMs: Math.round(performance.now() - start), keySource: source };
  } catch (err) {
    if (signal.aborted) throw error('TIMEOUT', `provider request timed out after ${timeoutMs}ms`);
    if (['HTTP_ERROR', 'INVALID_RESPONSE'].includes(err.code)) throw err;
    throw error('API_ERROR', err instanceof SyntaxError ? 'provider returned invalid JSON' : 'provider request failed');
  }
}
