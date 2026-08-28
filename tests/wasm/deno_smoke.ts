// End-to-end smoke test for the shipped freestanding WASM artifact, run in a
// real JS engine (Deno) to prove the loading semantics documented in
// docs/wasm.md as they leave the build.
//
//   deno run --allow-read=zig-out tests/wasm/deno_smoke.ts
//
// Exits non-zero on the first failure.

const WASM_PATH = "zig-out/wasm/paseto.wasm";

const STATUS_OK = 0;
const STATUS_CRYPTO_ERROR = 1;
const STATUS_INVALID_INPUT = 2;

const decoder = new TextDecoder();
const encoder = new TextEncoder();

function assert(cond: boolean, message: string): void {
  if (!cond) {
    console.error(`FAIL: ${message}`);
    Deno.exit(1);
  }
}

function assertStatus(actual: number, expected: number, op: string): void {
  assert(
    actual === expected,
    `${op}: expected status ${expected}, got ${actual}`,
  );
}

const moduleBytes = Deno.readFileSync(WASM_PATH);
const instance = new WebAssembly.Instance(new WebAssembly.Module(moduleBytes), {});

interface Exports {
  memory: WebAssembly.Memory;
  version(): number;
  allocate(len: number): number;
  free(ptr: number, len: number): void;
  resetAllocator(): void;
  seal(inputPtr: number, inputLen: number, outDescPtr: number): number;
  open(inputPtr: number, inputLen: number, outDescPtr: number): number;
  localKeyId(inputPtr: number, inputLen: number, outDescPtr: number): number;
  localKeyIdLen(): number;
  openResultHeaderLen(): number;
}

const e = instance.exports as unknown as Exports;

function view(): DataView {
  return new DataView(e.memory.buffer);
}

function u8(ptr: number, len: number): Uint8Array {
  return new Uint8Array(e.memory.buffer, ptr, len);
}

/** Allocate guest memory and copy host bytes in. */
function put(bytes: Uint8Array): number {
  const ptr = e.allocate(bytes.length);
  assert(ptr !== 0, `allocate(${bytes.length}) failed`);
  u8(ptr, bytes.length).set(bytes);
  return ptr;
}

/** Read a result descriptor, returning a host-owned copy of the bytes. */
function readResult(descPtr: number): Uint8Array {
  const resultPtr = view().getUint32(descPtr, true);
  const resultLen = view().getUint32(descPtr + 4, true);
  return u8(resultPtr, resultLen).slice();
}

function frameSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  message: Uint8Array,
  footer: Uint8Array,
  ia: Uint8Array,
  extraTrailing = 0,
): Uint8Array {
  const frame = new Uint8Array(
    76 + message.length + footer.length + ia.length + extraTrailing,
  );
  frame.set(key, 0);
  frame.set(nonce, 32);
  const dv = new DataView(frame.buffer);
  dv.setUint32(64, message.length, true);
  dv.setUint32(68, footer.length, true);
  dv.setUint32(72, ia.length, true);
  frame.set(message, 76);
  frame.set(footer, 76 + message.length);
  frame.set(ia, 76 + message.length + footer.length);
  return frame;
}

function frameOpen(
  key: Uint8Array,
  token: Uint8Array,
  ia: Uint8Array,
): Uint8Array {
  const frame = new Uint8Array(40 + token.length + ia.length);
  frame.set(key, 0);
  const dv = new DataView(frame.buffer);
  dv.setUint32(32, token.length, true);
  dv.setUint32(36, ia.length, true);
  frame.set(token, 40);
  frame.set(ia, 40 + token.length);
  return frame;
}

// --- ABI introspection ------------------------------------------------------

assertStatus(e.version(), 1, "version()");
assertStatus(e.localKeyIdLen(), 51, "localKeyIdLen()");
assertStatus(e.openResultHeaderLen(), 8, "openResultHeaderLen()");

// --- localKeyId: canonical k4.lid identifier --------------------------------

const key = new Uint8Array(32).fill(0xab);
let lidId: Uint8Array;
{
  e.resetAllocator();
  try {
    const inPtr = put(key);
    const descPtr = e.allocate(8);
    assertStatus(e.localKeyId(inPtr, key.length, descPtr), STATUS_OK, "localKeyId");
    lidId = readResult(descPtr);
  } finally {
    e.resetAllocator();
  }
}
const lidStr = decoder.decode(lidId);
assert(lidStr.startsWith("k4.lid.") && lidStr.length === 51, `localKeyId result: ${lidStr}`);

// --- seal + open round trip with footer and implicit assertion ---------------

const nonce = crypto.getRandomValues(new Uint8Array(32));
const message = encoder.encode('{"sub":"deno-smoke"}');
const footer = encoder.encode('{"kid":"deno"}');
const ia = encoder.encode("deno:v1");

let token: Uint8Array;
{
  e.resetAllocator();
  try {
    const inPtr = put(frameSeal(key, nonce, message, footer, ia));
    const descPtr = e.allocate(8);
    assertStatus(e.seal(inPtr, 76 + message.length + footer.length + ia.length, descPtr), STATUS_OK, "seal");
    token = readResult(descPtr);
  } finally {
    e.resetAllocator();
  }
}
const tokenStr = decoder.decode(token);
assert(tokenStr.startsWith("v4.local."), `seal result: ${tokenStr.slice(0, 32)}...`);

{
  e.resetAllocator();
  try {
    const inPtr = put(frameOpen(key, token, ia));
    const descPtr = e.allocate(8);
    assertStatus(e.open(inPtr, 40 + token.length + ia.length, descPtr), STATUS_OK, "open");
    const result = readResult(descPtr);
    const dv = new DataView(result.buffer, result.byteOffset, result.byteLength);
    const plaintextLen = dv.getUint32(0, true);
    const footerLen = dv.getUint32(4, true);
    const plaintext = result.slice(8, 8 + plaintextLen);
    const footerOut = result.slice(8 + plaintextLen, 8 + plaintextLen + footerLen);
    assert(
      decoder.decode(plaintext) === decoder.decode(message),
      "open plaintext mismatch",
    );
    assert(
      decoder.decode(footerOut) === decoder.decode(footer),
      "open footer mismatch",
    );
  } finally {
    e.resetAllocator();
  }
}

// --- negatives ---------------------------------------------------------------

// Wrong implicit assertion must fail authentication.
{
  e.resetAllocator();
  try {
    const wrongIa = encoder.encode("deno:other");
    const inPtr = put(frameOpen(key, token, wrongIa));
    const descPtr = e.allocate(8);
    assertStatus(
      e.open(inPtr, 40 + token.length + wrongIa.length, descPtr),
      STATUS_CRYPTO_ERROR,
      "open with wrong implicit assertion",
    );
  } finally {
    e.resetAllocator();
  }
}

// Tampered token must fail authentication.
{
  e.resetAllocator();
  try {
    const tampered = token.slice();
    tampered[tampered.length - 1] ^= 0x01;
    const inPtr = put(frameOpen(key, tampered, ia));
    const descPtr = e.allocate(8);
    assertStatus(
      e.open(inPtr, 40 + tampered.length + ia.length, descPtr),
      STATUS_CRYPTO_ERROR,
      "open with tampered token",
    );
  } finally {
    e.resetAllocator();
  }
}

// Low-memory pointers are rejected as invalid input.
{
  e.resetAllocator();
  try {
    const descPtr = e.allocate(8);
    assertStatus(e.seal(16, 76, descPtr), STATUS_INVALID_INPUT, "seal with low pointer");
  } finally {
    e.resetAllocator();
  }
}

// Trailing bytes in the input frame are rejected (exact consumption).
{
  e.resetAllocator();
  try {
    const inPtr = put(frameSeal(key, nonce, message, footer, ia, 1));
    const descPtr = e.allocate(8);
    assertStatus(
      e.seal(inPtr, 77 + message.length + footer.length + ia.length, descPtr),
      STATUS_INVALID_INPUT,
      "seal with trailing byte",
    );
  } finally {
    e.resetAllocator();
  }
}

console.log("deno wasm smoke: all checks passed");
