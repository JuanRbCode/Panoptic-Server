const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.resolve(__dirname, 'panoptic.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('[-] Error al conectar con SQLite:', err.message);
    } else {
        console.log('[+] Conectado a la base de datos SQLite.');
        initTables();
    }
});

function initTables() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            correo TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_name TEXT NOT NULL,
            room_code TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)`);


        db.run(`CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_socket_id TEXT UNIQUE NOT NULL,
            device_name TEXT NOT NULL,
            propietario TEXT,
            room_code TEXT,
            battery_level INTEGER DEFAULT 0,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(room_code) REFERENCES rooms(room_code) ON DELETE CASCADE
        )`);
    });
}

// --- USUARIOS ---
db.registerAdmin = (nombre, username, correo, pass, callback) => {
    db.get(`SELECT id FROM users WHERE username = ? OR correo = ?`, [username, correo], (err, row) => {
        if (err) return callback(err);
        if (row) return callback(new Error('El nombre de usuario o correo ya están registrados.'));

        bcrypt.hash(pass, 10, (err, hash) => {
            if (err) return callback(err);
            db.run(
                `INSERT INTO users (nombre, username, correo, password) VALUES (?, ?, ?, ?)`,
                [nombre, username, correo, hash],
                function (err) {
                    callback(err, this ? this.lastID : null);
                }
            );
        });
    });
};

db.verifyAdmin = (identifier, pass, callback) => {
    db.get(`SELECT * FROM users WHERE username = ? OR correo = ?`, [identifier, identifier], (err, user) => {
        if (err || !user) return callback(null, null);

        bcrypt.compare(pass, user.password, (err, match) => {
            if (err || !match) return callback(null, null);
            callback(null, user);
        });
    });
};

// Actualizar datos de usuario (nombre de usuario o contraseña opcional)
db.updateUser = (userId, newUsername, newPassword, callback) => {
    if (newPassword) {
        bcrypt.hash(newPassword, 10, (err, hash) => {
            if (err) return callback(err);
            db.run(
                `UPDATE users SET username = ?, password = ? WHERE id = ?`,
                [newUsername, hash, userId],
                callback
            );
        });
    } else {
        db.run(
            `UPDATE users SET username = ? WHERE id = ?`,
            [newUsername, userId],
            callback
        );
    }
};

// Eliminar usuario por completo (las salas y dispositivos se borran solos por CASCADE)
db.deleteUser = (userId, callback) => {
    db.run(`DELETE FROM users WHERE id = ?`, [userId], callback);
};

// --- SALAS ---
db.saveRoomForUser = (userId, roomCode, roomName, password, callback) => {
    db.run(
        `INSERT INTO rooms (room_name, room_code, password, user_id) VALUES (?, ?, ?, ?)`,
        [roomName, roomCode, password, userId],
        callback
    );
};

db.updateRoom = (userId, roomName, password, callback) => {
    db.run(
        `UPDATE rooms SET room_name = ?, password = ? WHERE user_id = ?`,
        [roomName, password, userId],
        callback
    );
};

db.deleteRoomByUser = (userId, callback) => {
    db.run(`DELETE FROM rooms WHERE user_id = ?`, [userId], callback);
};

db.getRoomByUser = (userId, callback) => {
    db.get(`SELECT * FROM rooms WHERE user_id = ?`, [userId], callback);
};

db.getRoom = (roomCode, callback) => {
    db.get(`SELECT * FROM rooms WHERE room_code = ?`, [roomCode], callback);
};

db.getRoomsByUser = (userId, callback) => {
    db.all(`SELECT * FROM rooms WHERE user_id = ?`, [userId], callback);
};

// --- DISPOSITIVOS ---
db.upsertDevice = (socketId, deviceName, propietario, roomCode, battery = 0, callback) => {
    db.run(
        `INSERT INTO devices (device_socket_id, device_name, propietario, room_code, battery_level, last_seen) 
         VALUES (?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT(device_socket_id) DO UPDATE SET 
         device_name = excluded.device_name, 
         propietario = excluded.propietario,
         battery_level = excluded.battery_level,
         room_code = excluded.room_code,
         last_seen = datetime('now')`,
        [socketId, deviceName, propietario, roomCode, battery],
        callback || (() => { })
    );
};

db.removeDevice = (socketId, callback) => {
    db.run(`DELETE FROM devices WHERE device_socket_id = ?`, [socketId], callback || (() => { }));
};

module.exports = db;