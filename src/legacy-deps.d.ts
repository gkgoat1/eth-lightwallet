/**
 * Minimal ambient shims for the legacy dependencies while Phase 2 keeps them.
 * They are intentionally narrow — just enough for the straight port — and are
 * deleted in Phase 3 when the legacy deps are swapped out.
 *
 * (tweetnacl / tweetnacl-util are kept at runtime long-term; they may get
 * proper types then.)
 */

declare module 'crypto-js' {
  const CryptoJS: any;
  export default CryptoJS;
}

declare module 'crypto-js/*' {
  const x: any;
  export default x;
}

declare module 'elliptic' {
  const elliptic: any;
  export default elliptic;
}

declare module 'bitcore-lib' {
  const BitCore: any;
  export default BitCore;
}

declare module 'bitcore-mnemonic' {
  const Mnemonic: any;
  export default Mnemonic;
}

declare module 'scrypt-async' {
  const ScryptAsync: any;
  export default ScryptAsync;
}

declare module 'tweetnacl' {
  const Nacl: any;
  export default Nacl;
}

declare module 'tweetnacl-util' {
  const NaclUtil: any;
  export default NaclUtil;
}

declare module 'ethereumjs-tx' {
  const Transaction: any;
  export default Transaction;
}

declare module 'ethereumjs-util' {
  const Util: any;
  export default Util;
}

declare module 'web3/*' {
  const x: any;
  export default x;
}

declare module 'rlp' {
  const Rlp: any;
  export default Rlp;
}
