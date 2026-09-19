// auth.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || '123fa9df769c89d5a02ad4374071776a992f2c5c3d50cab49219ce4f720f26a2';

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    if (!token) return res.status(401).json({ success: false, message: "Token requerido" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: "Token inválido" });
        req.user = user;
        next();
    });
};

// ¡IMPORTANTE! Exportarlo para que otros archivos puedan usarlo
module.exports = verifyToken;