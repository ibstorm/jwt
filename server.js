const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const port = 3000; // You can change this port

// Middleware to parse JSON request bodies
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Helper function to decode JWT using jsonwebtoken library
function decodeJwtWithLibrary(token) {
    try {
        // Decode without verifying signature - use for inspection only!
        // In a real application, for security, you MUST verify the signature.
        // For Cognito tokens, you'd typically fetch JWKS and use jwt.verify()
        // with the appropriate public key.
        const decoded = jwt.decode(token, { complete: true }); // complete: true gives header, payload, signature
        if (!decoded) {
            return { error: "Could not decode token with jsonwebtoken. Invalid token format or content." };
        }
        return {
            header: decoded.header,
            payload: decoded.payload
        };
    } catch (e) {
        return { error: `Failed to decode token: ${e.message}` };
    }
}

// API endpoint to decode JWT
app.post('/decode-jwt', (req, res) => {
    const token = req.body.token;

    if (!token) {
        return res.status(400).json({ error: "No token provided in the request body." });
    }

    // Log the token received by the backend for debugging
    console.log('Backend received token (first 50 chars):', token.substring(0, 50) + '...');
    if (token.length > 50) {
        console.log('Backend received token length:', token.length);
    }


    const decodedResult = decodeJwtWithLibrary(token);

    if (decodedResult.error) {
        // Log the error on the backend side as well
        console.error('Backend decoding error:', decodedResult.error);
        return res.status(400).json(decodedResult);
    } else {
        console.log('Backend successfully decoded token.');
        return res.json(decodedResult);
    }
});

// Start the server
app.listen(port, () => {
    console.log(`JWT Decoder app listening at http://localhost:${port}`);
    console.log(`Open your browser to http://localhost:${port}`);
});