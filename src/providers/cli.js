import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { providers } from './index.js';

export async function chatCli(name, { prompt, system, timeoutMs } = {}) {
  const provider = Object.hasOwn(providers, name) ? providers[name] : null;
  if (!provider) throw new Error(`unknown provider: ${name}`);
  if (provider.kind !== 'cli') throw new Error(`provider ${name} is not a CLI provider`);
  if (typeof prompt !== 'string') throw new Error('prompt must be a string');
  const timeout = timeoutMs ?? provider.timeoutMs;
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new Error('timeoutMs must be a positive finite number');
  }
  const input = system == null ? prompt : `${system}\n\n${prompt}`;
  const started = performance.now();
  return new Promise((resolve, reject) => {
    const child = spawn(provider.cmd[0], [...provider.cmd.slice(1), input], {
      cwd: tmpdir(),
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new Error(`provider ${name} timed out after ${timeout}ms`));
    }, timeout);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(0, 500); });
    child.on('error', error => finish(new Error(`provider ${name}: ${error.message}`)));
    child.on('close', (code, signal) => {
      if (code !== 0) {
        finish(new Error(`provider ${name} exited with code ${code}${signal ? ` (signal ${signal})` : ''}${stderr ? `: ${stderr}` : ''}`));
      } else {
        finish(null, { text: stdout.trim(), latencyMs: Math.round(performance.now() - started) });
      }
    });
  });
}
