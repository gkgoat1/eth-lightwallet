import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  minify: false,
  target: 'es2022',
  outExtensions({ format }) {
    return { js: format === 'cjs' ? '.cjs' : '.js' };
  },
  // Hoist default-export props onto module.exports so
  // require('eth-lightwallet').keystore works like 4.0.0 (also silences the
  // MIXED_EXPORTS warning).
  outputOptions: {
    exports: 'named',
  },
});
