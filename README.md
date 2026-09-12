# Panoptic Server 🛡️📱

Panoptic Server es el backend central de control y monitoreo remoto multi-tenant basado en **Node.js**, **Express** y **Socket.IO**. Permite enlazar de forma segura un panel de administración web con múltiples dispositivos Android en tiempo real.

---

## 🚀 Características Principales

- **Arquitectura Multi-Tenant (Salas):** Creación y gestión de salas privadas protegidas por contraseña y códigos únicos de acceso.
- **Autenticación Segura:** Sistema de registro y login para administradores respaldado por JSON Web Tokens (JWT) y contraseñas cifradas.
- **Streaming en Tiempo Real:** Canales de comunicación bidireccionales por WebSockets para transmisión de frames de cámara y fragmentos de audio (`socket.io`).
- **Control Remoto de Dispositivos:** Envío de comandos instantáneos hacia los teléfonos vinculados (como captura de fotos, control de cámaras frontal/trasera, gestión de audio y bloqueo/desbloqueo de pantalla).
- **Gestión de Base de Datos Local:** Uso de SQLite para la persistencia rápida y ligera de datos de usuarios, salas y dispositivos conectados.

---

## 🛠️ Tecnologías Utilizadas

- **Node.js** & **Express** (Servidor HTTP y API)
- **Socket.IO** (Comunicación bidireccional en tiempo real)
- **SQLite** (`sqlite3` para la persistencia de datos)
- **JSON Web Tokens (JWT)** & **Bcryptjs** (Seguridad y autenticación)

---

## 📦 Instalación y Configuración Local

1. Clona el repositorio:
   ```bash
   git clone [https://github.com/JuanRbCode/Panoptic-Server.git](https://github.com/JuanRbCode/Panoptic-Server.git)
   cd Panoptic-Server
   ```
