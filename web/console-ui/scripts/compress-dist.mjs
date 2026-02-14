import { readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { constants, gzipSync } from 'node:zlib';

const DIST_DIR = path.resolve(process.cwd(), 'dist');
const COMPRESSIBLE_EXTENSIONS = new Set([
  '.css',
  '.html',
  '.ico',
  '.js',
  '.json',
  '.map',
  '.mjs',
  '.svg',
  '.txt',
  '.xml'
]);

async function collectFiles(dirPath) {
  const entries = await readdir(dirPath, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        return collectFiles(fullPath);
      }
      return [fullPath];
    })
  );
  return nested.flat();
}

function isCompressible(filePath) {
  if (filePath.endsWith('.gz')) {
    return false;
  }
  const ext = path.extname(filePath).toLowerCase();
  return COMPRESSIBLE_EXTENSIONS.has(ext);
}

async function compressFile(filePath) {
  const fileStats = await stat(filePath);
  if (!fileStats.isFile()) {
    return;
  }

  const source = await readFile(filePath);
  const compressed = gzipSync(source, {
    level: constants.Z_BEST_COMPRESSION
  });
  await writeFile(`${filePath}.gz`, compressed);
}

async function main() {
  const files = await collectFiles(DIST_DIR);
  const targets = files.filter((filePath) => isCompressible(filePath));
  await Promise.all(targets.map((filePath) => compressFile(filePath)));
  console.log(`Created ${targets.length} gzipped asset(s) in ${DIST_DIR}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
