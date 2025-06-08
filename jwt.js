const jwt = require('jsonwebtoken');

// Function to perform Base64Url decoding and JSON parsing manually
function decodeJwtManually(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { error: "Invalid JWT format: token must have 3 parts." };
        }

        const headerEncoded = parts[0];
        const payloadEncoded = parts[1];

        // Base64Url decode: replace URL-safe chars and add padding if missing
        // Node.js Buffer handles Base64 decoding directly.
        // For Base64Url, we need to convert '-' to '+' and '_' to '/'
        // and then handle padding.
        const base64Header = headerEncoded.replace(/-/g, '+').replace(/_/g, '/');
        const base64Payload = payloadEncoded.replace(/-/g, '+').replace(/_/g, '/');

        // Add padding (Node.js Buffer.from('base64') needs proper padding)
        const addPadding = (s) => {
            const pad = s.length % 4;
            return s + '='.repeat(pad === 0 ? 0 : 4 - pad);
        };

        const headerDecoded = Buffer.from(addPadding(base64Header), 'base64').toString('utf8');
        const payloadDecoded = Buffer.from(addPadding(base64Payload), 'base64').toString('utf8');

        return {
            header: JSON.parse(headerDecoded),
            payload: JSON.parse(payloadDecoded)
        };
    } catch (e) {
        return { error: `Failed to manually decode token: ${e.message}` };
    }
}

// Function to decode JWT using jsonwebtoken library
function decodeJwtWithLibrary(token, verifySignature = false) {
    try {
        if (verifySignature) {
            // For verification, you'd need the public key (JWKS) from your identity provider
            // Example: (More complex in a real app, involving fetching JWKS and matching 'kid')
            // const jwksClient = require('jwks-rsa');
            // const client = jwksClient({
            //     jwksUri: 'https://cognito-idp.us-east-1.amazonaws.com/<userPoolId>/.well-known/jwks.json'
            // });
            // const decodedHeader = jwt.decode(token, { complete: true });
            // if (!decodedHeader || !decodedHeader.header.kid) {
            //     throw new Error("Invalid token: missing kid in header");
            // }
            // const key = await client.getSigningKey(decodedHeader.header.kid);
            // const publicKey = key.getPublicKey();
            // const decodedToken = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            return { error: "Signature verification not implemented in this example (requires JWKS fetching)." };
        } else {
            // Decode without verifying signature - use for inspection only!
            const decoded = jwt.decode(token, { complete: true }); // complete: true gives header, payload, signature
            if (!decoded) {
                return { error: "Could not decode token with jsonwebtoken." };
            }
            return {
                header: decoded.header,
                payload: decoded.payload
            };
        }
    } catch (e) {
        return { error: `Failed to decode token with jsonwebtoken: ${e.message}` };
    }
}

// Function to format Unix timestamps in the payload
function formatTimestampsInPayload(payload) {
    const readablePayload = { ...payload }; // Create a shallow copy
    const timestampKeys = ['exp', 'iat', 'auth_time'];

    for (const key of timestampKeys) {
        if (readablePayload[key] !== undefined && typeof readablePayload[key] === 'number') {
            try {
                // Convert Unix timestamp (seconds) to milliseconds for Date object
                const date = new Date(readablePayload[key] * 1000);
                readablePayload[`${key}_readable`] = date.toISOString(); // ISO 8601 format
            } catch (e) {
                // Ignore if conversion fails
            }
        }
    }
    return readablePayload;
}

// Your Access Token and ID Token strings
const accessTokenStr = "eyJraWQiOiJoczgzVE5VMDJjSUlzM1Q5MlZWTzlNMUR5VjM4MFBoUUdLT2VPdHN3T3hNPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI5NDE4ZjRlOC0yMGIxLTcwOWEtMDkwZS1kYTAzNmExZjdmODciLCJjb2duaXRvOmdyb3VwcyI6WyJhZHZpc29yIiwiYWRtaW4iXSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfNUdmOU1uY2QzIiwiY2xpZW50X2lkIjoiMnFzNXNvcW8zcG1uOHAzcjhtcGV1aHZyamkiLCJvcmlnaW5fanRpIjoiY2ZhNzVhOWYtM2JkZC00ZGZlLWIxZWMtYzc1NjViNTMxYjNhIiwiZXZlbnRfaWQiOiIyNGFkYzlkOC02M2NjLTQzODgtYTk4MS01MTZiMjdkY2IyZTkiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIiwiYXV0aF90aW1lIjoxNzQ5MzM2MTgyLCJleHAiOjE3NDkzMzk3ODIsImlhdCI6MTc0OTMzNjE4MiwianRpIjoiN2M2YWNhZTktYWY1NS00MTQ1LTk0YmEtMjEyMTJjMDNmMWQ5IiwidXNlcm5hbWUiOiI5NDE4ZjRlOC0yMGIxLTcwOWEtMDkwZS1kYTAzNmExZjdmODcifQ.mG8BzQxSAgVKGlsMtHhlyUgHooDcjgERVa33XYjPJO2YfgCwj1j3Nv6fdEBZ7a0KUK1SMZaAG_7AzCkZwCChEW1WcK7-TnYIJWfBbDBz7uGLAPYkraa9kusPQL07DMGqEhdmzvWYn562dw4VDKMbMd4XASt8pZCZ14PhKttdc2dniV-aOJdgkazpz0925o1ook1rfnduoGph1zV4BCflQrk75dZkhNYG2RVJN4_rIw6QOySYyC5dsjG4kgWFzX2lAD6Ehol3Qp8aBdC4N6MBcpy4QJhRTzVztJrXEzSOPUHym0d06L4riwV1IosYcdXDA_S9YHSVrEhXgZCPDsKOw";
const idTokenStr = "eyJraWQiOiJUZWtzWXhWaVFiTEdLZ0N0NjRPeTFHZkpRSENCV05aVVhcL2xOXC9IWnZ3cTQ9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI5NDE4ZjRlOC0yMGIxLTcwOWEtMDkwZS1kYTAzNmExZjdmODciLCJjb2duaXRvOmdyb3VwcyI6WyJhZHZpc29yIiwiYWRtaW4iXSwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xXzVHZjlNbmNkMyIsInBob25lX251bWJlcl92ZXJpZmllZCI6ZmFsc2UsImNvZ25pdG86dXNlcm5hbWUiOiI5NDE4ZjRlOC0yMGIxLTcwOWEtMDkwZS1kYTAzNmExZjdmODciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJiYiIsImdpdmVuX25hbWUiOiJCYWhyYW0iLCJvcmlnaW5fanRpIjoiY2ZhNzVhOWYtM2JkZC00ZGZlLWIxZWMtYzc1NjViNTMxYjNhIiwiY29nbml0bzpyb2xlcyI6WyJhcm46YXdzOmlhbTo6NDkxMDg1NDA1NDA1OnJvbGVcL3NpZ25hbGlmeS1hZHZpc29yLXJvbGUiLCJhcm46YXdzOmlhbTo6NDkxMDg1NDA1NDA1OnJvbGVcL3NpZ25hbGlmeS1hZG1pbi1yb2xlIl0sImF1ZCI6IjJxczVzb3FvM3BtbjhwM3I4bXBldWh2cmppIiwiZXZlbnRfaWQiOiIyNGFkYzlkOC02M2NjLTQzODgtYTk4MS01MTZiMjdkY2IyZTkiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTc0OTMzNjE4MiwicGhvbmVfbnVtYmVyIjoiKzE2NDc2NjczMzE4IiwiZXhwIjoxNzQ5MzM5NzgyLCJpYXQiOjE3NDkzMzYxODIsImZhbWlseV9uYW1lIjoiSGFqaWFuIiwianRpIjoiMDU3MDk3ZjEtOWFlOS00ZDVmLWExZDQtMzA0MDVlOTAzMTYwIiwiZW1haWwiOiJiYWhyYW1Ac2lnbmFsaWZ5LmNvIn0.OtEdVepuQjK4tPK2rE4skcw6RxCnVJjZ6GIFblKTcMgv3Sy4P7rEdeLc-N-Uwh-6mEzJvsiJx5p-u_TqP2oyczkdm9KD3WnXJXg9DBcZbesP8Dw7irHAqNh6y47Z57rWCLYwzM1XpwW4By2TkLvOiEsRHYPMmcguH58GUkWV59DVBuHZ0APMFSUg2Ibt5X5t50zV-DkV0tmo61H_S4N6OZjb9AD-uP2AkJZWYvdK3vyNtmESGWzgWqim_aPYM3l244GiQt0LD28xuZaN1i_kAuCyT8_jzu-yRDy5ZFQTo28asZUyOOW4fAodHo3xBPtRnRdj6t76kiqTJvoR45s8oQ";

console.log("--- Decoding Access Token (using jsonwebtoken) ---");
let decodedAccessToken = decodeJwtWithLibrary(accessTokenStr);
if (decodedAccessToken.payload) {
    decodedAccessToken.payload = formatTimestampsInPayload(decodedAccessToken.payload);
}
console.log(JSON.stringify(decodedAccessToken, null, 2));

console.log("\n--- Decoding ID Token (using jsonwebtoken) ---");
let decodedIdToken = decodeJwtWithLibrary(idTokenStr);
if (decodedIdToken.payload) {
    decodedIdToken.payload = formatTimestampsInPayload(decodedIdToken.payload);
}
console.log(JSON.stringify(decodedIdToken, null, 2));

// // Uncomment the following to see manual decoding
// console.log("\n--- Manual Decoding of ID Token (for demonstration) ---");
// let manuallyDecodedIdToken = decodeJwtManually(idTokenStr);
// if (manuallyDecodedIdToken.payload) {
//     manuallyDecodedIdToken.payload = formatTimestampsInPayload(manuallyDecodedIdToken.payload);
// }
// console.log(JSON.stringify(manuallyDecodedIdToken, null, 2));