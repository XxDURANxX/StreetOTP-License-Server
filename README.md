# StreetOTP License Server

Sistema completo de gestión de licencias para la extensión StreetOTP de Chrome.

## Características

- ✅ Panel administrativo web moderno y seguro
- ✅ Generación de licencias con múltiples tipos (1 mes, 1 año, sin límite)
- ✅ Sistema de autenticación seguro con JWT
- ✅ Base de datos SQLite para almacenamiento
- ✅ Registro de auditoría completo
- ✅ Sistema de solicitudes de licencia
- ✅ Notificaciones de vencimiento (programado)
- ✅ API RESTful para validación de licencias
- ✅ Seguridad con rate limiting y helmet

## Instalación

### Requisitos Previos

- Node.js 16+ instalado
- npm o yarn

### Pasos de Instalación

1. **Navegar al directorio del servidor**
   ```bash
   cd c:\Users\A¨x\Desktop\StreetOTP-License-Server
   ```

2. **Instalar dependencias**
   ```bash
   npm install
   ```

3. **Configurar variables de entorno**
   
   Abre el archivo `.env` y cambia las siguientes credenciales por las tuyas:
   ```
   ADMIN_USERNAME=tu_usuario
   ADMIN_PASSWORD=tu_contraseña_segura
   ADMIN_EMAIL=tu@email.com
   JWT_SECRET=tu_secreto_jwt_muy_largo_y_seguro
   LICENSE_SECRET_KEY=tu_secreto_de_licencia_muy_largo_y_seguro
   ```

   **IMPORTANTE:** Cambia todas las contraseñas y secretos por valores seguros y únicos.

4. **Iniciar el servidor**
   ```bash
   npm start
   ```

   El servidor iniciará en `http://localhost:3000`

## Uso

### Acceder al Panel Administrativo

1. Abre tu navegador y ve a `http://localhost:3000`
2. Ingresa las credenciales configuradas en `.env`
3. Verás el dashboard con estadísticas

### Crear una Licencia

1. Ve a la sección "Licencias"
2. Haz clic en "Crear Licencia"
3. Selecciona el tipo de licencia:
   - **1 Mes**: Vence en 30 días
   - **1 Año**: Vence en 365 días
   - **Sin Límite**: No expira nunca
4. Opcionalmente, ingresa el email del usuario
5. Haz clic en "Crear Licencia"
6. La clave de licencia se generará y podrás copiarla

### Gestionar Solicitudes

1. Ve a la sección "Solicitudes"
2. Verás las solicitudes pendientes de usuarios
3. Puedes aprobar (crea una licencia automáticamente) o rechazar solicitudes

### Ver Auditoría

1. Ve a la sección "Auditoría"
2. Verás un registro completo de todas las acciones realizadas en el sistema

## API Endpoints

### Autenticación

- `POST /api/auth/login` - Iniciar sesión
- `GET /api/auth/verify` - Verificar token

### Licencias

- `POST /api/licenses` - Crear licencia (requiere autenticación)
- `GET /api/licenses` - Obtener todas las licencias (requiere autenticación)
- `GET /api/licenses/:id` - Obtener licencia específica (requiere autenticación)
- `PUT /api/licenses/:id` - Actualizar licencia (requiere autenticación)
- `DELETE /api/licenses/:id` - Eliminar licencia (requiere autenticación)
- `POST /api/licenses/validate` - Validar licencia (para extensión)
- `POST /api/licenses/activate` - Activar licencia (para extensión)

### Solicitudes

- `POST /api/license-requests` - Crear solicitud de licencia
- `GET /api/license-requests` - Obtener solicitudes (requiere autenticación)
- `PUT /api/license-requests/:id` - Actualizar solicitud (requiere autenticación)

### Dashboard

- `GET /api/dashboard/stats` - Obtener estadísticas (requiere autenticación)

### Auditoría

- `GET /api/audit-log` - Obtener registro de auditoría (requiere autenticación)

## Configurar la Extensión

Para conectar la extensión StreetOTP con este servidor:

1. Abre la extensión en Chrome
2. Ve a la pestaña "Configuración"
3. En "URL del Servidor de Licencias", ingresa:
   - Local: `http://localhost:3000`
   - Producción: `https://tu-dominio.com`
4. Haz clic en "Guardar Configuración"
5. Activa una licencia con una clave generada desde el panel administrativo

## Seguridad

### Medidas de Seguridad Implementadas

1. **Autenticación JWT**: Tokens seguros con expiración de 24 horas
2. **Rate Limiting**: Límite de 100 solicitudes por IP cada 15 minutos
3. **Helmet**: Headers de seguridad HTTP
4. **Bcrypt**: Hashing de contraseñas con 12 rounds
5. **CORS**: Control de acceso cruzado
6. **Auditoría**: Registro completo de todas las acciones
7. **Validación de Inputs**: Sanitización de todos los datos

### Recomendaciones de Seguridad

1. **Cambiar credenciales por defecto**: Modifica inmediatamente las credenciales en `.env`
2. **Usar HTTPS**: En producción, usa HTTPS con certificado SSL
3. **Firewall**: Configura firewall para restringir acceso
4. **Backups**: Realiza backups regulares de la base de datos
5. **Monitoreo**: Monitorea los logs de auditoría regularmente
6. **Actualizaciones**: Mantén Node.js y dependencias actualizadas

## Notificaciones de Vencimiento

El sistema incluye un cron job que se ejecuta diariamente a las 9 AM para:

1. Identificar licencias que expiran en 7 días
2. Marcar licencias expiradas como "expired"
3. (Opcional) Enviar notificaciones por email

Para habilitar notificaciones por email, configura las variables de email en `.env`:

```
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=tu_email@gmail.com
EMAIL_PASSWORD=tu_app_password
EMAIL_FROM=StreetOTP License System <noreply@streetotp.com>
```

## Estructura del Proyecto

```
StreetOTP-License-Server/
├── database/
│   └── licenses.db          # Base de datos SQLite
├── public/
│   ├── index.html           # Panel administrativo HTML
│   ├── styles.css           # Estilos del panel
│   └── app.js               # Lógica del panel
├── .env                     # Variables de entorno
├── package.json             # Dependencias
├── server.js                # Servidor principal
└── README.md               # Este archivo
```

## Solución de Problemas

### El servidor no inicia

- Verifica que Node.js esté instalado: `node --version`
- Verifica que el puerto 3000 esté disponible
- Revisa los logs de error en la consola

### No puedo iniciar sesión

- Verifica las credenciales en `.env`
- Asegúrate de haber reiniciado el servidor después de cambiar `.env`
- Revisa si hay errores en la consola del servidor

### La extensión no valida licencias

- Verifica que la URL del servidor esté correcta en la configuración de la extensión
- Asegúrate de que el servidor esté ejecutándose
- Revisa los logs de auditoría en el panel administrativo

## Desarrollo

### Modo de Desarrollo

Para desarrollo con auto-reload:

```bash
npm install -g nodemon
npm run dev
```

### Base de Datos

La base de datos se crea automáticamente en `database/licenses.db`. Puedes usar herramientas como DB Browser for SQLite para inspeccionarla.

## Licencia

Este proyecto es parte de StreetOTP y está protegido por derechos de autor.

## Soporte

Para soporte técnico, contacta a: algenis2506@gmail.com
