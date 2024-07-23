import crypto from "crypto";

interface Payload {
  [key: string]: any;
}

function base64UrlEncode(data: string): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64UrlDecode(data: string): string {
  data = data.replace(/-/g, "+").replace(/_/g, "/");
  while (data.length % 4) {
    data += "=";
  }
  return Buffer.from(data, "base64").toString("utf8");
}

export function encode_jwt(
  secret: string,
  id: string | number,
  payload: Payload,
  ttl?: number,
  aud?: string,
  iss?: string
): string {
  const header = { alg: "HS256", typ: "JWT" };
  const iat = Math.floor(Date.now() / 1000);
  const exp = ttl ? iat + ttl : undefined;
  const body = { ...payload, sub: id, iat, exp, aud, iss };

  const base64UrlHeader = base64UrlEncode(JSON.stringify(header));
  const base64UrlBody = base64UrlEncode(JSON.stringify(body));
  const signature = crypto
    .createHmac("sha256", secret)
    .update(`${base64UrlHeader}.${base64UrlBody}`)
    .digest("base64");

  const base64UrlSignature = base64UrlEncode(signature);

  return `${base64UrlHeader}.${base64UrlBody}.${base64UrlSignature}`;
}

export function decode_jwt(
  secret: string,
  token: string
): {
  id: string;
  payload: Payload;
  expires_at?: Date;
  issued_at?: Date;
  audience?: string;
  issuer?: string;
} {
  const [header, payload, signature] = token.split(".");

  const base64UrlHeader = base64UrlDecode(header);
  const base64UrlPayload = base64UrlDecode(payload);

  const expectedSignature = base64UrlEncode(
    crypto
      .createHmac("sha256", secret)
      .update(`${header}.${payload}`)
      .digest("base64")
  );

  if (expectedSignature !== signature) {
    throw new Error("Invalid token signature");
  }

  const decodedPayload = JSON.parse(base64UrlPayload);

  return {
    id: decodedPayload.sub,
    payload: decodedPayload,
    expires_at: decodedPayload.exp
      ? new Date(decodedPayload.exp * 1000)
      : undefined,
    issued_at: decodedPayload.iat
      ? new Date(decodedPayload.iat * 1000)
      : undefined,
    audience: decodedPayload.aud,
    issuer: decodedPayload.iss,
  };
}

export function validate_jwt(secret: string, token: string): boolean {
  try {
    const decoded = decode_jwt(secret, token);
    return !decoded.expires_at || decoded.expires_at > new Date();
  } catch {
    return false;
  }
}
