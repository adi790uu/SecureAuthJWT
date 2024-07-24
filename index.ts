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

async function createHmac(secret: string, message: string) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(message)
  );
  return Buffer.from(signature).toString("base64");
}

export async function encode_jwt(
  secret: string,
  id: string | number,
  payload: Payload,
  ttl?: number,
  aud?: string,
  iss?: string
): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const iat = Math.floor(Date.now() / 1000);
  const exp = ttl ? iat + ttl : undefined;
  const body = { ...payload, sub: id, iat, exp, aud, iss };

  const base64UrlHeader = base64UrlEncode(JSON.stringify(header));
  const base64UrlBody = base64UrlEncode(JSON.stringify(body));
  const signature = await createHmac(
    secret,
    `${base64UrlHeader}.${base64UrlBody}`
  );

  const base64UrlSignature = base64UrlEncode(signature);

  return `${base64UrlHeader}.${base64UrlBody}.${base64UrlSignature}`;
}

export async function decode_jwt(
  secret: string,
  token: string
): Promise<{
  id: string;
  payload: Payload;
  expires_at?: Date;
  issued_at?: Date;
  audience?: string;
  issuer?: string;
}> {
  const [header, payload, signature] = token.split(".");
  const base64UrlPayload = base64UrlDecode(payload);

  const expectedSignature = await createHmac(secret, `${header}.${payload}`);

  if (base64UrlEncode(expectedSignature) !== signature) {
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

export async function validate_jwt(
  secret: string,
  token: string
): Promise<boolean> {
  try {
    const decoded = await decode_jwt(secret, token);
    return !decoded.expires_at || decoded.expires_at > new Date();
  } catch {
    return false;
  }
}
