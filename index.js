require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto')

const port = process.env.PORT || 3000;

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;
const AUTH0_MGMT_AUDIENCE = process.env.AUTH0_MGMT_AUDIENCE;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

let PUBLIC_KEY_CACHE = null;

async function getPublicKey() {
    if (PUBLIC_KEY_CACHE) return PUBLIC_KEY_CACHE;

    const resp = await fetch(`https://${AUTH0_DOMAIN}/pem`);
    const cert = await resp.text();

    if (!cert.includes("BEGIN CERTIFICATE")) {
        throw new Error("Invalid CERTIFICATE received");
    }

    const publicKey = crypto.createPublicKey(cert).export({ type: "spki", format: "pem" });

    PUBLIC_KEY_CACHE = publicKey;
    console.log("Public key extracted & cached.");
    return publicKey;
}

async function authMiddleware(req, res, next) {
    try {
        const header = req.headers["authorization"];
        if (!header) return res.status(401).json({ error: "No token" });

        const token = header.split(" ")[1];
        if (!token) return res.status(401).json({ error: "Invalid token format" });

        const decoded = jwt.decode(token);

        if (!decoded || !decoded.exp) {
            return res.status(401).json({ error: "Invalid token (cannot decode)" });
        }

        const timeLeft = decoded.exp - Math.floor(Date.now() / 1000);

        if (timeLeft < 60 && req.headers["x-refresh-token"]) {
            const refreshToken = req.headers["x-refresh-token"];

            const refreshResponse = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                    grant_type: "refresh_token",
                    client_id: AUTH0_CLIENT_ID,
                    client_secret: AUTH0_CLIENT_SECRET,
                    refresh_token: refreshToken
                })
            });

            const refreshData = await refreshResponse.json();

            if (refreshData.error) {
                return res.status(401).json({ error: "Refresh failed", details: refreshData });
            }

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

    if (mgmtToken.error) {
        return res.status(400).json({ error: mgmtToken });
    }

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

    res.json({
        message: "User created",
        user: data
    });
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

    if (data.error) {
        return res.status(401).json({ error: data.error, details: data.error_description });
    }

    res.json({
        access_token: data.access_token,
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
