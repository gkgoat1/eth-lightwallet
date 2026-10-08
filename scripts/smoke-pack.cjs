/**
 * Packaging smoke test — packs the library with `npm pack`, installs the
 * tarball into a temp dir, and verifies:
 *   1. CJS: require() exposes keystore/signing/txutils/encryption/upgrade
 *   2. ESM: import exposes the same named + default surface
 *   3. A functional pin: derive an address from the golden fixture in both
 * Run AFTER `npm run build`. Node-only script (CJS) by design.
 */
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const repoRoot = path.join(__dirname, '..');
const golden = require('../test/golden/generated/vault-4.0.0.json');

function sh(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim();
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lw-smoke-'));
try {
  const packOut = sh('npm', ['pack', '--pack-destination', tmp], repoRoot);
  const tarball = path.join(tmp, packOut.split('\n').pop());
  console.log('packed:', path.basename(tarball));

  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'smoke-consumer', version: '0.0.0' }));
  sh('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', tarball], tmp);

  const checkSnippet = (label, importExpr) => `
    (async () => {
      const lw = await (${importExpr});
      const names = ['keystore','signing','txutils','encryption','upgrade'];
      for (const n of names) {
        if (!lw[n]) throw new Error('${label}: missing export ' + n);
      }
      const g = ${JSON.stringify({ input: golden.vault.input, kdf: golden.kdf, addrs: golden.firstFiveAddresses })};
      lw.keystore.createVault(
        { password: g.input.password, seedPhrase: g.input.mnemonic, salt: g.input.salt, hdPathString: g.input.hdPathString },
        (err, ks) => {
          if (err) throw err;
          const pw = Uint8Array.from(Buffer.from(g.kdf.pwDerivedKeyHex, 'hex'));
          ks.generateNewAddress(pw, 5);
          const got = JSON.stringify(ks.getAddresses());
          if (got !== JSON.stringify(g.addrs)) throw new Error('${label}: address mismatch\\n' + got);
          console.log('${label}: OK — 5 golden addresses reproduced');
        },
      );
    })();
  `;

  // 1. CJS require
  execFileSync(
    process.execPath,
    ['-e', checkSnippet('CJS require', "Promise.resolve(require('eth-lightwallet'))")],
    { cwd: tmp, stdio: 'inherit' },
  );

  // 2. ESM named+default import
  execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      "import lw, { keystore } from 'eth-lightwallet';" +
        "if (keystore !== lw.keystore) throw new Error('ESM default/named mismatch');" +
        'globalThis.__lw = lw;',
    ],
    { cwd: tmp, stdio: 'inherit' },
  );
  console.log('ESM import: OK — named + default exports consistent');

  // 3. ESM functional pin
  execFileSync(
    process.execPath,
    ['--input-type=module', '-e', checkSnippet('ESM import', "import('eth-lightwallet')")],
    { cwd: tmp, stdio: 'inherit' },
  );

  // 4. Types resolve under node16 + bundler, from BOTH an ESM consumer
  // (.mts, static import) and a CJS consumer (.cts, import= + require-use).
  const tsBin = path.join(repoRoot, 'node_modules', '.bin', 'tsc');
  fs.writeFileSync(
    path.join(tmp, 'consumer.mts'),
    "import lw, { keystore, txutils, signing, encryption, upgrade } from 'eth-lightwallet';\n" +
      'const salt: string = keystore.DEFAULT_SALT;\n' +
      'export { lw, txutils, signing, encryption, upgrade, salt };\n',
  );
  fs.writeFileSync(
    path.join(tmp, 'consumer.cts'),
    "import lw = require('eth-lightwallet');\n" +
      'const salt: string = lw.keystore.DEFAULT_SALT;\n' +
      'export { lw, salt };\n',
  );
  for (const mr of ['node16', 'bundler']) {
    const files = mr === 'node16' ? ['consumer.mts', 'consumer.cts'] : ['consumer.mts'];
    const tsconfig = {
      compilerOptions: { strict: true, noEmit: true, moduleResolution: mr, module: mr === 'node16' ? 'node16' : 'esnext', target: 'es2022', skipLibCheck: true, types: [] },
      files,
    };
    fs.writeFileSync(path.join(tmp, `tsconfig.${mr}.json`), JSON.stringify(tsconfig));
    execFileSync(tsBin, ['-p', `tsconfig.${mr}.json`], { cwd: tmp, stdio: 'inherit' });
    console.log(`types (moduleResolution=${mr}): OK`);
  }

  console.log('\nSMOKE PASS');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
