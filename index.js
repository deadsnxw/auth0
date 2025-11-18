require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const port = process.env.PORT || 3000;

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;
const AUTH0_MGMT_AUDIENCE = process.env.AUTH0_MGMT_AUDIENCE;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const ENC_KEY = crypto.randomBytes(32);
const IV_LENGTH = 16;

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv("aes-256-cbc", ENC_KEY, iv);
    let encrypted = cipher.update(text, "utf8", "base64");
    encrypted += cipher.final("base64");
    return iv.toString("base64") + ":" + encrypted;
}

function decrypt(enc) {
    const [ivStr, encrypted] = enc.split(":");
    const iv = Buffer.from(ivStr, "base64");
    const decipher = crypto.createDecipheriv("aes-256-cbc", ENC_KEY, iv);
    let dec = decipher.update(encrypted, "base64", "utf8");
    dec += decipher.final("utf8");
    return dec;
}

let PUBLIC_KEY_CACHE = null;

async function getPublicKey() {
    if (PUBLIC_KEY_CACHE) return PUBLIC_KEY_CACHE;

    const resp = await fetch(`https://${AUTH0_DOMAIN}/pem`);
    const cert = await resp.text();

    if (!cert.includes("BEGIN CERTIFICATE")) {
        throw new Error("Invalid CERTIFICATE received");
    }

    PUBLIC_KEY_CACHE = cert;
    console.log("Public key cached.");
    return PUBLIC_KEY_CACHE;
}

function createEncryptedJWT(payload) {
    const encrypted = encrypt(JSON.stringify(payload));
    return jwt.sign(
        { data: encrypted, enc: "AES256" },
        process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
        { algorithm: "HS256", expiresIn: "1h" }
    );
}

async function authMiddleware(req, res, next) {
    try {
        const header = req.headers["authorization"];
        if (!header) return res.status(401).json({ error: "No token" });

        const token = header.split(" ")[1];
        if (!token) return res.status(401).json({ error: "Invalid token format" });

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'), {
                algorithms: ["HS256"]
            });

            if (!decoded.data) return res.status(401).json({ error: "Encrypted payload missing" });
            
            const decrypted = JSON.parse(decrypt(decoded.data));
            req.user = decrypted;
            
            return next();
        } catch (jwtError) {
            console.log("Custom JWT verification failed, trying Auth0 token:", jwtError.message);
        }

        const decoded = jwt.decode(token);
        if (!decoded || !decoded.exp) return res.status(401).json({ error: "Invalid token" });

        const timeLeft = decoded.exp - Math.floor(Date.now() / 1000);
        if (timeLeft < 60 && req.headers["x-refresh-token"]) {
            const refreshToken = req.headers["x-refresh-token"];
            const refreshResp = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                    grant_type: "refresh_token",
                    client_id: AUTH0_CLIENT_ID,
                    client_secret: AUTH0_CLIENT_SECRET,
                    refresh_token: refreshToken
                })
            });
            const refreshData = await refreshResp.json();
            if (refreshData.error) return res.status(401).json({ error: "Refresh failed", details: refreshData });
            res.setHeader("x-new-access-token", refreshData.access_token);
        }

        const publicKey = await getPublicKey();
        const verified = jwt.verify(token, publicKey, {
            algorithms: ["RS256"],
            audience: AUTH0_AUDIENCE,
            issuer: `https://${AUTH0_DOMAIN}/`
        });

        req.user = verified;
        next();
    } catch (err) {
        console.error("JWT verify error:", err);
        return res.status(401).json({ error: "Token invalid", details: err.message });
    }
}

app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;

    const mgmtTokenResp = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            audience: AUTH0_MGMT_AUDIENCE,
            grant_type: "client_credentials"
        })
    });

    const mgmtToken = await mgmtTokenResp.json();
    if (mgmtToken.error) return res.status(400).json({ error: mgmtToken });

    const createResp = await fetch(`${AUTH0_MGMT_AUDIENCE}users`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${mgmtToken.access_token}`
        },
        body: JSON.stringify({
            email,
            password,
            connection: "Username-Password-Authentication"
        })
    });

    const data = await createResp.json();
    if (data.error) return res.status(400).json(data);

    res.json({ message: "User created", user: data });
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;

    const tokenResponse = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            grant_type: "password",
            username: login,
            password: password,
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            audience: AUTH0_AUDIENCE,
            scope: "openid profile email offline_access"
        })
    });

    const data = await tokenResponse.json();
    if (data.error) return res.status(401).json({ error: data.error, details: data.error_description });

    const idTokenPayload = jwt.decode(data.id_token);
    const encryptedToken = createEncryptedJWT({
        sub: idTokenPayload?.sub || login,
        email: login,
        auth0_data: idTokenPayload
    });

    res.json({
        access_token: encryptedToken,
        refresh_token: data.refresh_token,
        expires_in: data.expires_in,
        id_token: data.id_token,
        token_type: data.token_type
    });
});

app.get('/api/me', authMiddleware, (req, res) => {
    res.json({ user: req.user });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});