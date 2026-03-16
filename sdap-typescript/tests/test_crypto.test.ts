import { describe, it, expect } from "vitest";
import {
  sha256Hex,
  sha256Bytes,
  canonicalize,
  signJws,
  verifyJws,
  signDetached,
  verifyDetached,
  performEcdh,
  deriveSessionKeys,
  encryptPayload,
  decryptPayload,
} from "../src/index.js";
import {
  generateEd25519KeyPair,
  generateX25519KeyPair,
} from "../src/identity/index.js";

describe("SHA-256 hashing", () => {
  it("hashes known input correctly", () => {
    const data = new TextEncoder().encode("hello");
    const hex = sha256Hex(data);
    // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    expect(hex).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
  });

  it("returns bytes as Uint8Array", () => {
    const data = new TextEncoder().encode("test");
    const bytes = sha256Bytes(data);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(32);
  });

  it("sha256Hex and sha256Bytes are consistent", () => {
    const data = new TextEncoder().encode("consistency-test");
    const hex = sha256Hex(data);
    const bytes = sha256Bytes(data);
    expect(Buffer.from(bytes).toString("hex")).toBe(hex);
  });
});

describe("JCS canonicalization", () => {
  it("sorts object keys", () => {
    const obj = { z: 1, a: 2, m: 3 };
    const result = new TextDecoder().decode(canonicalize(obj));
    expect(result).toBe('{"a":2,"m":3,"z":1}');
  });

  it("handles nested objects", () => {
    const obj = { b: { y: 1, x: 2 }, a: 3 };
    const result = new TextDecoder().decode(canonicalize(obj));
    expect(result).toBe('{"a":3,"b":{"x":2,"y":1}}');
  });

  it("handles arrays", () => {
    const obj = { arr: [3, 1, 2], key: "val" };
    const result = new TextDecoder().decode(canonicalize(obj));
    expect(result).toBe('{"arr":[3,1,2],"key":"val"}');
  });

  it("handles null and boolean values", () => {
    const obj = { a: null, b: true, c: false };
    const result = new TextDecoder().decode(canonicalize(obj));
    expect(result).toBe('{"a":null,"b":true,"c":false}');
  });

  it("handles string with special chars", () => {
    const obj = { key: "hello\nworld" };
    const result = new TextDecoder().decode(canonicalize(obj));
    expect(result).toBe('{"key":"hello\\nworld"}');
  });

  it("produces deterministic output", () => {
    const obj = { x: 1, a: "test", z: [1, 2, 3] };
    const r1 = Buffer.from(canonicalize(obj)).toString("hex");
    const r2 = Buffer.from(canonicalize(obj)).toString("hex");
    expect(r1).toBe(r2);
  });

  it("same output as expected JCS for simple example", () => {
    // Known JCS test vector
    const obj = { b: 2, a: 1 };
    const result = new TextDecoder().decode(canonicalize(obj));
    expect(result).toBe('{"a":1,"b":2}');
  });
});

describe("JWS signing and verification", () => {
  it("signs and verifies payload", async () => {
    const kp = generateEd25519KeyPair("test-key");
    const payload = new TextEncoder().encode("test payload");

    const jws = await signJws(payload, kp.privateKey, kp.keyId);
    expect(jws.split(".")).toHaveLength(3);

    const recovered = await verifyJws(jws, kp.publicKey);
    expect(new TextDecoder().decode(recovered)).toBe("test payload");
  });

  it("rejects tampered JWS", async () => {
    const kp = generateEd25519KeyPair("key");
    const payload = new TextEncoder().encode("data");
    const jws = await signJws(payload, kp.privateKey, kp.keyId);

    // Tamper with the signature
    const parts = jws.split(".");
    const tampered = `${parts[0]}.${parts[1]}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
    await expect(verifyJws(tampered, kp.publicKey)).rejects.toThrow();
  });

  it("rejects wrong public key", async () => {
    const kp1 = generateEd25519KeyPair("k1");
    const kp2 = generateEd25519KeyPair("k2");
    const payload = new TextEncoder().encode("data");
    const jws = await signJws(payload, kp1.privateKey, kp1.keyId);
    await expect(verifyJws(jws, kp2.publicKey)).rejects.toThrow();
  });
});

describe("Detached JWS", () => {
  it("signs and verifies detached payload", async () => {
    const kp = generateEd25519KeyPair("key");
    const data = new TextEncoder().encode("canonical data");

    const jws = await signDetached(data, kp.privateKey, kp.keyId);
    const parts = jws.split(".");
    expect(parts).toHaveLength(3);
    expect(parts[1]).toBe(""); // empty payload

    const valid = await verifyDetached(jws, data, kp.publicKey);
    expect(valid).toBe(true);
  });

  it("rejects tampered data in detached JWS", async () => {
    const kp = generateEd25519KeyPair("key");
    const data = new TextEncoder().encode("canonical data");
    const jws = await signDetached(data, kp.privateKey, kp.keyId);

    const tampered = new TextEncoder().encode("tampered data");
    const valid = await verifyDetached(jws, tampered, kp.publicKey);
    expect(valid).toBe(false);
  });

  it("rejects wrong public key for detached", async () => {
    const kp1 = generateEd25519KeyPair("k1");
    const kp2 = generateEd25519KeyPair("k2");
    const data = new TextEncoder().encode("data");
    const jws = await signDetached(data, kp1.privateKey, kp1.keyId);
    const valid = await verifyDetached(jws, data, kp2.publicKey);
    expect(valid).toBe(false);
  });
});

describe("X25519 ECDH", () => {
  it("derives the same shared secret from both sides", () => {
    const kpA = generateX25519KeyPair("a");
    const kpB = generateX25519KeyPair("b");

    const secretA = performEcdh(kpA.privateKey, kpB.publicKey);
    const secretB = performEcdh(kpB.privateKey, kpA.publicKey);

    expect(Buffer.from(secretA).toString("hex")).toBe(
      Buffer.from(secretB).toString("hex")
    );
  });

  it("produces 32-byte secret", () => {
    const kpA = generateX25519KeyPair("a");
    const kpB = generateX25519KeyPair("b");
    const secret = performEcdh(kpA.privateKey, kpB.publicKey);
    expect(secret.length).toBe(32);
  });
});

describe("Session key derivation", () => {
  it("derives 32-byte keys", () => {
    const secret = new Uint8Array(32).fill(1);
    const nonceA = new Uint8Array(32).fill(2);
    const nonceB = new Uint8Array(32).fill(3);
    const { encryptKey, macKey } = deriveSessionKeys(
      secret,
      nonceA,
      nonceB,
      "test-session"
    );
    expect(encryptKey.length).toBe(32);
    expect(macKey.length).toBe(32);
  });

  it("is deterministic with same inputs", () => {
    const secret = new Uint8Array(32).fill(42);
    const nonceA = new Uint8Array(16).fill(10);
    const nonceB = new Uint8Array(16).fill(20);
    const { encryptKey: k1, macKey: m1 } = deriveSessionKeys(
      secret,
      nonceA,
      nonceB,
      "session-id"
    );
    const { encryptKey: k2, macKey: m2 } = deriveSessionKeys(
      secret,
      nonceA,
      nonceB,
      "session-id"
    );
    expect(Buffer.from(k1).toString("hex")).toBe(
      Buffer.from(k2).toString("hex")
    );
    expect(Buffer.from(m1).toString("hex")).toBe(
      Buffer.from(m2).toString("hex")
    );
  });

  it("produces different keys for different sessions", () => {
    const secret = new Uint8Array(32).fill(1);
    const nonceA = new Uint8Array(16).fill(2);
    const nonceB = new Uint8Array(16).fill(3);
    const { encryptKey: k1 } = deriveSessionKeys(
      secret,
      nonceA,
      nonceB,
      "session-1"
    );
    const { encryptKey: k2 } = deriveSessionKeys(
      secret,
      nonceA,
      nonceB,
      "session-2"
    );
    expect(Buffer.from(k1).toString("hex")).not.toBe(
      Buffer.from(k2).toString("hex")
    );
  });
});

describe("AES-256-GCM encryption", () => {
  it("encrypts and decrypts a payload", async () => {
    const key = new Uint8Array(32).fill(7);
    const plaintext = new TextEncoder().encode("Hello, SDAP!");
    const sessionId = "test-session";
    const seq = 1;
    const senderDid = "did:sdap:example.com:sender";

    const jwe = await encryptPayload(plaintext, key, sessionId, seq, senderDid);
    expect(typeof jwe).toBe("string");
    expect(jwe.split(".")).toHaveLength(4);

    const recovered = await decryptPayload(jwe, key, sessionId, seq, senderDid);
    expect(new TextDecoder().decode(recovered)).toBe("Hello, SDAP!");
  });

  it("rejects wrong key", async () => {
    const key = new Uint8Array(32).fill(1);
    const wrongKey = new Uint8Array(32).fill(2);
    const plaintext = new TextEncoder().encode("secret");
    const jwe = await encryptPayload(
      plaintext,
      key,
      "sess",
      1,
      "did:sdap:a.com:x"
    );
    await expect(
      decryptPayload(jwe, wrongKey, "sess", 1, "did:sdap:a.com:x")
    ).rejects.toThrow();
  });

  it("rejects wrong session ID (AAD mismatch)", async () => {
    const key = new Uint8Array(32).fill(1);
    const plaintext = new TextEncoder().encode("secret");
    const jwe = await encryptPayload(
      plaintext,
      key,
      "sess-A",
      1,
      "did:sdap:a.com:x"
    );
    await expect(
      decryptPayload(jwe, key, "sess-B", 1, "did:sdap:a.com:x")
    ).rejects.toThrow();
  });

  it("rejects key of wrong length", async () => {
    const key = new Uint8Array(16).fill(1);
    await expect(
      encryptPayload(
        new TextEncoder().encode("data"),
        key,
        "s",
        1,
        "did:sdap:a.com:x"
      )
    ).rejects.toThrow();
  });
});
