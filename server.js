const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const pool = require('./db');
const verifyToken = require('./auth');

const app = express();
app.use(express.json());
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const JWT_SECRET = process.env.JWT_SECRET || '123fa9df769c89d5a02ad4374071776a992f2c5c3d50cab49219ce4f720f26a2';

// ----------------------------------------------------
// INICIALIZACIÓN DE TABLAS EN MYSQL (Automática al arrancar)
// ----------------------------------------------------
async function initDB() {
    try {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            username VARCHAR(50) UNIQUE NOT NULL,
            correo VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        `);

        await pool.query(`
          CREATE TABLE IF NOT EXISTS rooms (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nombre VARCHAR(100) NOT NULL,
            codigo VARCHAR(10) UNIQUE NOT NULL,
            contrasena VARCHAR(255) NOT NULL,
            owner_id INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
          )
        `);

        await pool.query(`
          CREATE TABLE IF NOT EXISTS devices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            device_uid VARCHAR(100) UNIQUE NOT NULL,
            nombre VARCHAR(100) NOT NULL,
            room_id INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
          )
        `);
        console.log('[Database] Tablas verificadas/creadas correctamente en MySQL.');
    } catch (err) {
        console.error('[Database Error] Error al inicializar tablas:', err);
    }
}
initDB();

// ----------------------------------------------------
// RUTAS REST: AUTENTICACIÓN Y GESTIÓN DE USUARIOS
// ----------------------------------------------------

// Registrar Usuario
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, username, correo, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query(
            'INSERT INTO users (name, username, correo, password) VALUES (?, ?, ?, ?)',
            [name, username, correo, hashedPassword]
        );

        res.status(201).json({ success: true, message: "Usuario registrado con éxito" });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Login de Usuario (JWT)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { correo, password } = req.body;
        const [rows] = await pool.query('SELECT * FROM users WHERE correo = ?', [correo]);

        if (rows.length === 0) {
            return res.status(401).json({ success: false, message: "Credenciales inválidas" });
        }

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ success: false, message: "Credenciales inválidas" });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ success: true, token, user: { id: user.id, name: user.name, username: user.username, correo: user.correo } });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Actualizar datos de Perfil de Usuario
app.put('/api/auth/profile', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, username, correo, password } = req.body;

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.query(
                'UPDATE users SET name = ?, username = ?, correo = ?, password = ? WHERE id = ?',
                [name, username, correo, hashedPassword, userId]
            );
        } else {
            await pool.query(
                'UPDATE users SET name = ?, username = ?, correo = ? WHERE id = ?',
                [name, username, correo, userId]
            );
        }

        res.json({ success: true, message: "Perfil actualizado con éxito" });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Eliminar Cuenta de Usuario (Elimina en cascada sus salas y dispositivos)
app.delete('/api/auth/profile', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        await pool.query('DELETE FROM users WHERE id = ?', [userId]);
        res.json({ success: true, message: "Cuenta y datos asociados eliminados correctamente" });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ----------------------------------------------------
// RUTAS REST: GESTIÓN DE SALAS (SEGURIZADAS CON JWT)
// ----------------------------------------------------

// Crear Sala (Solo si está logueado)
app.post('/api/rooms/create', verifyToken, async (req, res) => {
    try {
        const { nombre, codigo, contrasena } = req.body;
        const owner_id = req.user.id; // Asignado automáticamente por el token del usuario logueado
        const hashedRoomPass = await bcrypt.hash(contrasena, 10);

        await pool.query(
            'INSERT INTO rooms (nombre, codigo, contrasena, owner_id) VALUES (?, ?, ?, ?)',
            [nombre, codigo, hashedRoomPass, owner_id]
        );

        res.status(201).json({ success: true, message: "Sala creada con éxito" });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Obtener solo las salas del usuario autenticado
app.get('/api/rooms', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const [rooms] = await pool.query('SELECT id, nombre, codigo, created_at FROM rooms WHERE owner_id = ?', [userId]);
        res.json({ success: true, rooms });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Actualizar Sala (Solo si pertenece al usuario autenticado)
app.put('/api/rooms/:id', verifyToken, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;
        const { nombre, codigo, contrasena } = req.body;

        // Validar que la sala pertenezca al usuario
        const [rooms] = await pool.query('SELECT * FROM rooms WHERE id = ? AND owner_id = ?', [roomId, userId]);
        if (rooms.length === 0) {
            return res.status(403).json({ success: false, message: "No autorizado o sala no encontrada" });
        }

        if (contrasena) {
            const hashedRoomPass = await bcrypt.hash(contrasena, 10);
            await pool.query(
                'UPDATE rooms SET nombre = ?, codigo = ?, contrasena = ? WHERE id = ?',
                [nombre, codigo, hashedRoomPass, roomId]
            );
        } else {
            await pool.query(
                'UPDATE rooms SET nombre = ?, codigo = ? WHERE id = ?',
                [nombre, codigo, roomId]
            );
        }

        res.json({ success: true, message: "Sala actualizada con éxito" });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Eliminar Sala (Solo si pertenece al usuario autenticado)
app.delete('/api/rooms/:id', verifyToken, async (req, res) => {
    try {
        const roomId = req.params.id;
        const userId = req.user.id;

        const [result] = await pool.query('DELETE FROM rooms WHERE id = ? AND owner_id = ?', [roomId, userId]);
        if (result.affectedRows === 0) {
            return res.status(403).json({ success: false, message: "No autorizado o sala no encontrada" });
        }

        res.json({ success: true, message: "Sala eliminada con éxito" });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ----------------------------------------------------
// WEBSOCKETS (PANEL Y DISPOSITIVOS MÓVILES)
// ----------------------------------------------------

io.on('connection', (socket) => {
    console.log(`[+] Conexión establecida: ${socket.id}`);

    // 1. Autenticación del panel web por JWT
    socket.on('authenticate_panel', (token) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            socket.user = decoded;
            socket.emit('auth_success', { message: "Panel autenticado" });
            console.log(`[🔐] Panel autenticado para usuario ID: ${decoded.id}`);
        } catch (err) {
            socket.emit('auth_error', { message: "Token inválido" });
            socket.disconnect();
        }
    });

    // 1.1 Unirse a la sala de sockets seleccionada
    socket.on('join_room_panel', (roomCode) => {
        const formattedRoomCode = roomCode ? roomCode.trim().toUpperCase() : '';
        socket.join(formattedRoomCode);
        console.log(`[🖥️ Panel Web] Se unió a la sala socket: ${formattedRoomCode}`);

        global.activeDevices = global.activeDevices || {};
        const devicesInRoom = Object.values(global.activeDevices).filter(d => d.roomCode === formattedRoomCode);
        socket.emit('update_devices', devicesInRoom);
    });

    // 2. Registro del dispositivo móvil validando la Sala
    socket.on('register_device_to_room', async (data) => {
        try {
            const { deviceUid, name, roomCode, roomPassword, battery } = data;
            const formattedRoomCode = roomCode ? roomCode.trim().toUpperCase() : '';

            const [room] = await pool.query('SELECT * FROM rooms WHERE codigo = ?', [formattedRoomCode]);

            if (!room || room.length === 0) {
                console.log(`[Auth Error] La sala ${formattedRoomCode} no existe.`);
                socket.emit('room_auth_error', { message: 'La sala no existe' });
                return;
            }

            const isValidPassword = await bcrypt.compare(roomPassword, room[0].contrasena);
            if (!isValidPassword) {
                console.log(`[Auth Error] Contraseña incorrecta para la sala ${formattedRoomCode}`);
                socket.emit('room_auth_error', { message: 'Contraseña incorrecta' });
                return;
            }

            socket.join(formattedRoomCode);

            global.activeDevices = global.activeDevices || {};
            global.activeDevices[socket.id] = {
                id: socket.id,
                socketId: socket.id,
                deviceUid,
                name: name || 'Android Device',
                roomCode: formattedRoomCode,
                battery: battery || 100
            };

            socket.emit('device_registered_success');

            const devicesInRoom = Object.values(global.activeDevices).filter(d => d.roomCode === formattedRoomCode);
            io.to(formattedRoomCode).emit('update_devices', devicesInRoom);

            console.log(`[Dispositivo Conectado] ${name} aceptado en la sala ${formattedRoomCode}`);
        } catch (error) {
            console.error('Error en registro de dispositivo:', error);
        }
    });

    // 3. Comandos y Streams
    socket.on('send_command_to_device', (data) => {
        const { targetId, action, ...extra } = data;
        console.log(`[Comando] Reenviando acción '${action}' al targetId: ${targetId}`);
        io.to(targetId).emit('command_to_phone', { action, ...extra });
    });

    socket.on('camera_frame', (data) => {
        if (typeof data === 'object' && data.status === 'stopped') {
            io.emit('camera_frame', { deviceId: socket.id, frame: null });
        } else {
            io.emit('camera_frame', { deviceId: socket.id, frame: data });
        }
    });

    // Audio que va del Celular hacia la PC (Escuchar el entorno del celular)
    socket.on('audio_chunk', (base64Audio) => {
        io.emit('audio_chunk', { deviceId: socket.id, chunk: base64Audio });
    });

    // Audio bidireccional corregido: Del Panel Web (Microfóno de la PC) hacia el Celular
    socket.on('client_audio_chunk', (data) => {
        const { targetId, chunk } = data;
        if (targetId) {
            io.to(targetId).emit('play_audio_chunk', { chunk });
        }
    });

    // 4. Manejo de Desconexiones
    socket.on('disconnect', () => {
        global.activeDevices = global.activeDevices || {};
        if (global.activeDevices[socket.id]) {
            const roomCode = global.activeDevices[socket.id].roomCode;
            delete global.activeDevices[socket.id];

            const devicesInRoom = Object.values(global.activeDevices).filter(d => d.roomCode === roomCode);
            io.to(roomCode).emit('update_devices', devicesInRoom);
            console.log(`[Desconectado] Socket ${socket.id} removido de la sala ${roomCode}`);
        }
    });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor Panoptic corriendo en puerto ${PORT}`);
});