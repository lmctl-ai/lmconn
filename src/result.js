// Command envelope helpers. stdout carries exactly one JSON object per run.

export const ok = (result) => ({ ok: true, result });
export const fail = (code, message, extra = {}) => ({ ok: false, error: { code, message, ...extra } });

export function emit(envelope) {
  process.stdout.write(JSON.stringify(envelope) + '\n');
}

// Usage errors exit 2, runtime failures exit 1, success exits 0.
export function emitFail(code, message, extra) {
  emit(fail(code, message, extra));
  return code === 'USAGE' ? 2 : 1;
}
