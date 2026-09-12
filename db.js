const mysql = require('mysql2');
const bcrypt = require('bcryptjs');

// Creamos la conexión usando las variables de entorno de Railway
const db = mysql.createPool({
    host: process.env.MYSQLHOST || 'localhost',
    user: process.env.MYSQLUSER || 'root',
    password: process.env.MYSQLPASSWORD || '',
    database: process.env.MYSQLDATABASE || 'railway',
    port: process.env.MYSQLPORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Comprobar la conexión inicial
db.getConnection((err, connection) => {
    if (err) {
        console.error('[-] Error al conectar con MySQL:', err.message);
    } else {
        console.log('[+] Conectado a la base de datos MySQL en Railway.');
        initTables();
        connection.release();
    }
});

function initTables() {
    db.query(`CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nombre VARCHAR(255) NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        correo VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
    )`, (err) => { if (err) console.error("Error creando tabla users:", err); });

    db.query(`CREATE TABLE IF NOT EXISTS rooms (
        id INT AUTO_INCREMENT PRIMARY KEY,
        room_name VARCHAR(255) NOT NULL,
        room_code VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        user_id INT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`, (err) => { if (err) console.error("Error creando tabla rooms:", err); });

    db.query(`CREATE TABLE IF NOT EXISTS devices (
        id INT AUTO_INCREMENT PRIMARY KEY,
        device_socket_id VARCHAR(255) UNIQUE NOT NULL,
        device_name VARCHAR(255) NOT NULL,
        propietario VARCHAR(255),
        room_code VARCHAR(255),
        battery_level INT DEFAULT 0,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY(room_code) REFERENCES rooms(room_code) ON DELETE CASCADE
    )`, (err) => { if (err) console.error("Error creando tabla devices:", err); });
}

// --- USUARIOS ---
db.registerAdmin = (nombre, username, correo, pass, callback) => {
    db.query(`SELECT id FROM users WHERE username = ? OR correo = ?`, [username, correo], (err, rows) => {
        if (err) return callback(err);
        if (rows.length > 0) return callback(new Error('El nombre de usuario o correo ya están registrados.'));

        bcrypt.hash(pass, 10, (err, hash) => {
            if (err) return callback(err);
            db.query(
                `INSERT INTO users (nombre, username, correo, password) VALUES (?, ?, ?, ?)`,
                [nombre, username, correo, hash],
                function (err, result) {
                    callback(err, result ? result.insertId : null);
                }
            );
        });
    });
};

db.verifyAdmin = (identifier, pass, callback) => {
    db.query(`SELECT * FROM users WHERE username = ? OR correo = ?`, [identifier, identifier], (err, rows) => {
        if (err || rows.length === 0) return callback(null, null);
        const user = rows[0];

        bcrypt.compare(pass, user.password, (err, match) => {
            if (err || !match) return callback(null, null);
            callback(null, user);
        });
    });
};

db.updateUser = (userId, newUsername, newPassword, callback) => {
    if (newPassword) {
        bcrypt.hash(newPassword, 10, (err, hash) => {
            if (err) return callback(err);
            db.query(
                `UPDATE users SET username = ?, password = ? WHERE id = ?`,
                [newUsername, hash, userId],
                callback
            );
        });
    } else {
        db.query(
            `UPDATE users SET username = ? WHERE id = ?`,
            [newUsername, userId],
            callback
        );
    }
};

db.deleteUser = (userId, callback) => {
    db.query(`DELETE FROM users WHERE id = ?`, [userId], callback);
};

// --- SALAS ---
db.saveRoomForUser = (userId, roomCode, roomName, password, callback) => {
    db.query(
        `INSERT INTO rooms (room_name, room_code, password, user_id) VALUES (?, ?, ?, ?)`,
        [roomName, roomCode, password, userId],
        callback
    );
};

db.updateRoomDetails = (roomId, userId, newRoomName, newPassword, callback) => {
    db.query(
        `UPDATE rooms SET room_name = ?, password = ? WHERE id = ? AND user_id = ?`,
        [newRoomName, newPassword, roomId, userId],
        callback
    );
};

db.deleteRoomById = (roomId, userId, callback) => {
    db.query(`DELETE FROM rooms WHERE id = ? AND user_id = ?`, [roomId, userId], callback);
};

db.updateRoom = (userId, roomName, password, callback) => {
    db.query(
        `UPDATE rooms SET room_name = ?, password = ? WHERE user_id = ?`,
        [roomName, password, userId],
        callback
    );
};

db.deleteRoomByUser = (userId, callback) => {
    db.query(`DELETE FROM rooms WHERE user_id = ?`, [userId], callback);
};

db.getRoomByUser = (userId, callback) => {
    db.query(`SELECT * FROM rooms WHERE user_id = ?`, [userId], (err, rows) => {
        callback(err, rows ? rows[0] : null);
    });
};

db.getRoom = (roomCode, callback) => {
    db.query(`SELECT * FROM rooms WHERE room_code = ?`, [roomCode], (err, rows) => {
        callback(err, rows ? rows[0] : null);
    });
};

db.getRoomsByUser = (userId, callback) => {
    db.query(`SELECT * FROM rooms WHERE user_id = ?`, [userId], callback);
};

// --- DISPOSITIVOS ---
db.upsertDevice = (socketId, deviceName, propietario, roomCode, battery = 0, callback) => {
    db.query(
        `INSERT INTO devices (device_socket_id, device_name, propietario, room_code, battery_level, last_seen) 
         VALUES (?, ?, ?, ?, ?, NOW())
         ON DUPLICATE KEY UPDATE 
         device_name = VALUES(device_name), 
         propietario = VALUES(propietario),
         battery_level = VALUES(battery_level),
         room_code = VALUES(room_code),
         last_seen = NOW()`,
        [socketId, deviceName, propietario, roomCode, battery],
        callback || (() => { })
    );
};

db.removeDevice = (socketId, callback) => {
    db.query(`DELETE FROM devices WHERE device_socket_id = ?`, [socketId], callback || (() => { }));
};

module.exports = db;