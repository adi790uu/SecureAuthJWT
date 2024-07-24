import test, { describe } from "node:test";
import { validate_jwt, decode_jwt, encode_jwt } from "..";
import { strict as assert } from "node:assert";

describe("JWT tests", () => {
  const secret = "Rand3om";
  const id = 1234;
  const payload = { name: "Aditya", admin: true };
  const ttl = 3600;
  const aud = "https://api.jwt.com";
  const iss = "https://api.issuer.com";

  test("Successfull encoding of token with various parameters", async () => {
    const token = await encode_jwt(secret, id, payload, ttl, aud, iss);
    assert.ok(token);
    assert.equal(typeof token, "string");
  });
  test("should decode JWT and verify payload", async () => {
    const token = await encode_jwt(secret, id, payload, ttl, aud, iss);
    const decoded = await decode_jwt(secret, token);
    assert.equal(decoded.id, id);
    assert.equal(decoded.payload.name, payload.name);
    assert.equal(decoded.payload.admin, payload.admin);
    assert.equal(decoded.payload.aud, aud);
    assert.equal(decoded.payload.iss, iss);
  });

  test("should throw error for invalid JWT signature", async () => {
    const token = await encode_jwt(secret, id, payload, ttl, aud, iss);
    const [header, body] = token.split(".");
    const invalidToken = `${header}.${body}.invalidsignature`;

    assert.throws(() => decode_jwt(secret, invalidToken), {
      message: "Invalid token signature",
    });
  });

  test("should validate a valid JWT", async () => {
    const token = await encode_jwt(secret, id, payload, ttl, aud, iss);
    const isValid = await validate_jwt(secret, token);
    assert.equal(isValid, true);
  });

  test("should invalidate an expired JWT", async () => {
    const expiredTTL = -3600;
    const token = await encode_jwt(secret, id, payload, expiredTTL, aud, iss);
    const isValid = await validate_jwt(secret, token);
    assert.equal(isValid, false);
  });

  test("should invalidate a JWT with invalid signature", async () => {
    const token = await encode_jwt(secret, id, payload, ttl, aud, iss);
    const [header, body] = token.split(".");
    const invalidToken = `${header}.${body}.invalidsignature`;

    const isValid = validate_jwt(secret, invalidToken);
    assert.equal(isValid, false);
  });
});
