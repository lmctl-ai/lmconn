// Only a provider's expires_in creates this deadline. Chunking is a timer ABI requirement.
const MAX_TIMER = 2147483647;
export function providerDeadline(end, hooks = {}) {
  const now = hooks.now || (() => performance.now()), schedule = hooks.setTimer || setTimeout, clear = hooks.clearTimer || clearTimeout;
  const controller = new AbortController(); let timer;
  const expired = () => Object.assign(new Error('OAuth device authorization expired'), { code: 'EXPIRED' });
  const check = () => { if (now() >= end && !controller.signal.aborted) controller.abort(expired()); if (controller.signal.aborted) throw controller.signal.reason; };
  function arm() { const remaining = end - now(); if (remaining <= 0) { controller.abort(expired()); return; } timer = schedule(arm, Math.min(remaining, MAX_TIMER)); }
  arm();
  const race = promise => new Promise((resolve, reject) => {
    const abort = () => reject(controller.signal.reason);
    if (controller.signal.aborted) { Promise.resolve(promise).catch(() => {}); abort(); return; }
    controller.signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => controller.signal.removeEventListener('abort', abort));
  });
  async function sleep(milliseconds) {
    const target = Math.min(end, now() + milliseconds);
    while (now() < target) {
      check();
      if (hooks.wait) await race(hooks.wait(Math.min(target - now(), MAX_TIMER)));
      else {
        let wake;
        try { await race(new Promise(resolve => { wake = schedule(resolve, Math.min(target - now(), MAX_TIMER)); })); }
        finally { if (wake !== undefined) clear(wake); }
      }
    }
    check();
  }
  return { now, signal: controller.signal, check, race, sleep, close() { if (timer !== undefined) clear(timer); } };
}
