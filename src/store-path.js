import fs from 'node:fs';
import path from 'node:path';
import { securityError } from './oauth-security.js';
const fail = () => { throw securityError('Credential store path is not private or safe', 'STORE_SECURITY'); };
function owner(st) { if (process.geteuid && st.uid !== process.geteuid()) fail(); }
function regular(file, create = false) {
  let fd;
  try {
    const flags = fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0);
    try { fd = fs.openSync(file, flags | (create ? fs.constants.O_CREAT | fs.constants.O_EXCL : 0), 0o600); }
    catch (err) { if (create && err.code === 'EEXIST') fd = fs.openSync(file, flags); else throw err; }
    const st = fs.fstatSync(fd), named = fs.lstatSync(file);
    owner(st);
    if (!st.isFile() || st.nlink !== 1 || named.isSymbolicLink() || named.dev !== st.dev || named.ino !== st.ino) fail();
    if (process.platform !== 'win32') { fs.fchmodSync(fd, 0o600); if ((fs.fstatSync(fd).mode & 0o777) !== 0o600) fail(); }
    return { dev: st.dev, ino: st.ino };
  } catch (err) { if (!create && err.code === 'ENOENT') return null; fail(); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function ancestors(directory) {
  const parsed = path.parse(directory); let current = parsed.root;
  for (const part of directory.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    let st; try { st = fs.lstatSync(current); } catch (err) { if (err.code === 'ENOENT') { fs.mkdirSync(current, { mode: 0o700 }); st = fs.lstatSync(current); } else fail(); }
    if (st.isSymbolicLink()) {
      // macOS /var and /tmp are root-owned system links; user-controlled links are never accepted.
      const parent = fs.statSync(path.dirname(current));
      if (!process.geteuid || st.uid !== 0 || parent.uid !== 0 || (parent.mode & 0o022)) fail();
      st = fs.statSync(current);
    }
    if (!st.isDirectory()) fail();
    if (process.geteuid && st.uid !== 0 && st.uid !== process.geteuid()) fail();
    if (process.platform !== 'win32' && (st.mode & 0o022) && !(st.mode & 0o1000) && current !== directory) fail();
  }
}
export function secureStorePath(filename, protectedStore = false) {
  if (process.platform === 'win32' && protectedStore) throw securityError('Protected credential stores require native Windows ACL support', 'STORE_SECURITY');
  const file = path.resolve(filename), directory = path.dirname(file);
  ancestors(directory);
  const st = fs.lstatSync(directory); owner(st); if (st.isSymbolicLink() || !st.isDirectory() || (st.mode & 0o1000)) fail();
  if (process.platform !== 'win32') { fs.chmodSync(directory, 0o700); if ((fs.statSync(directory).mode & 0o777) !== 0o700) fail(); }
  // The owner-only directory seals the check/open interval against other principals.
  for (const suffix of ['-journal', '-wal', '-shm']) regular(file + suffix);
  return { file, identity: regular(file, true) };
}
