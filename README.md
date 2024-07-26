# SecureAuthJWT

**SecureAuthJWT** is a package designed for generating, decoding, and validating JWT tokens.

## Features

- Generate JWT tokens
- Decode JWT tokens
- Validate JWT tokens

## Generating a JWT Token

To generate a JWT token, follow these steps:

1. Use the `encode_jwt` function (Note: It is an asynchronous function).
2. Pass the following parameters:
   - `secret`: (string) The secret key used for encoding the token.
   - `id`: (string | number) The unique identifier for the token.
   - `payload`: (Payload) The payload data to be included in the token.
   - `ttl`: (number, optional) The time-to-live (TTL) for the token in seconds.
   - `aud`: (string, optional) The audience for the token.
   - `iss`: (string, optional) The issuer of the token.

3. The function will return a JWT token.

## Decoding a JWT Token

To generate a JWT token, follow these steps:

1. Use the `decode_jwt` function (Note: It is an asynchronous function).
2. Pass the following parameters:
   - `secret`: (string) The secret key used for encoding the token.
   - `token`: (string) The jwt token to be decoded.
3. The function will return an object which would contain various used in the payload.

## Validate a JWT Token

To generate a JWT token, follow these steps:

1. Use the `validate_jwt` function (Note: It is an asynchronous function).
2. Pass the following parameters:
   - `secret`: (string) The secret key used for encoding the token.
   - `token`: (string) The jwt token to be decoded.
3. The function will return a boolean value.

Find us out on npm : https://www.npmjs.com/package/secureauthjwt<br>
Try out the package : https://secureauthjwt.vercel.app/
