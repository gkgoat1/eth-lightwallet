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
});
