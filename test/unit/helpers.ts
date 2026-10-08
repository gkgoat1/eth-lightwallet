/** Small helpers for the callback-style API. */

export type Cb<T> = (err: unknown, value?: T) => void;

/** Promisify a (err, value) callback-style function. */
export function promisify1<A = any, R = any>(fn: (a: A, cb: Cb<R>) => void): (a: A) => Promise<R> {
  return (a: A) =>
    new Promise<R>((resolve, reject) => {
      fn(a, (err, value) => (err ? reject(err) : resolve(value as R)));
    });
}

export function promisify2<A = any, B = any, R = any>(fn: (a: A, b: B, cb: Cb<R>) => void): (a: A, b: B) => Promise<R> {
  return (a: A, b: B) =>
    new Promise<R>((resolve, reject) => {
      fn(a, b, (err, value) => (err ? reject(err) : resolve(value as R)));
    });
}
