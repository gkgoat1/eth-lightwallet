/**
 * Port of test/txutils.js (mocha/chai) → vitest.
 */
import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { TxUtils, TARGET } from './target';

const require = createRequire(import.meta.url);
const fixtures = require('../fixtures/txutils.json');

describe(`Utils [target=${TARGET}]`, () => {
  describe('_getTypesFromAbi', () => {
    for (const f of fixtures.valid) {
      it(`returns valid types of function "${f.func}"`, () => {
        const types = TxUtils._getTypesFromAbi(f.abi, f.func);

        expect(types).toEqual(f.types);
      });
    }
  });

  describe('functionTx', () => {
    for (const f of fixtures.valid) {
      it(`correct transaction generated (${f.func})`, () => {
        const tx = TxUtils.functionTx(f.abi, f.func, f.args, f.txObject);

        expect(tx).toBe(f.funcTx);
      });
    }
  });

  describe('createdContractAddress', () => {
    for (const f of fixtures.valid) {
      it(`correct contract address is generated (${f.func})`, () => {
        const address = TxUtils.createdContractAddress(f.fromAddress, f.txObject.nonce);

        expect(address).toBe(f.contractAddress);
      });
    }
  });

  describe('createContractTx valueTx', () => {
    for (const f of fixtures.valid) {
      it(`createContractTx returns the same as valueTx and contractAddress (${f.func})`, () => {
        const contractTxData = TxUtils.createContractTx(f.fromAddress, f.txObject);
        const txData = TxUtils.valueTx(f.txObject);
        const address = TxUtils.createdContractAddress(f.fromAddress, f.txObject.nonce);

        expect(address).toBe(contractTxData.addr);
        expect(txData).toBe(contractTxData.tx);
      });
    }
  });
});
