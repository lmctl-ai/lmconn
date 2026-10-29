// lmmock exec owns this process. EOF requests portable graceful server shutdown.
process.stdin.resume();
process.stdin.on('end', () => process.exit(0));
