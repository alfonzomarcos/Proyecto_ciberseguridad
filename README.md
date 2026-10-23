# Banco Demo: aplicación web con controles básicos de ciberseguridad

Proyecto educativo que simula la banca online de un banco ficticio. Los usuarios pueden iniciar sesión, ver su saldo y sus movimientos, y hacer transferencias. **Todos los datos son ficticios.** No usar con información real.

## Objetivo

Mostrar un primer acercamiento práctico al desarrollo seguro: identificar riesgos habituales en aplicaciones web (autenticación, control de acceso, validación de datos) y verificar con pruebas que las protecciones funcionan.

## Tecnologías

- **Frontend:** HTML, CSS y JavaScript (sin frameworks)
- **Backend:** Node.js + Express
- **Datos:** en memoria (arrays de JavaScript), sin base de datos
- **Librerías de seguridad:** `bcryptjs` (hash de contraseñas), `helmet` (cabeceras HTTP), `express-session` (sesiones)

## Cómo ejecutarlo

Requiere Node.js 18 o superior.

```bash
npm install
npm start          # abre http://localhost:3000
npm test           # ejecuta las pruebas de seguridad
```

Usuarios de prueba:

| Usuario | Contraseña          |
|---------|---------------------|
| ana     | `Ana-Demo-2024!`    |
| marcos  | `Marcos-Demo-2024!` |

## Medidas de seguridad implementadas

| Riesgo | Medida | Dónde |
|--------|--------|-------|
| Contraseñas expuestas | Hash con bcrypt (costo 12); nunca se guardan ni se registran en texto plano | `server.js` |
| Fuerza bruta | Bloqueo de 15 min tras 5 intentos fallidos (por IP + usuario) | `/api/login` |
| Enumeración de usuarios | Mensaje genérico y comparación de hash aunque el usuario no exista | `/api/login` |
| Session fixation | Se regenera la sesión al iniciar sesión | `/api/login` |
| Robo de sesión | Cookie `httpOnly`, `sameSite=strict`, `secure` en producción, expiración de 15 min | `session()` |
| **Acceso a datos de otros (IDOR)** | El servidor comprueba en cada request que la cuenta pertenezca al usuario de la sesión | `getOwnedAccount()` |
| CSRF | Token por sesión exigido en operaciones que modifican datos + cookie SameSite | `requireCsrf()` |
| Inyección y datos inválidos | Validación por lista blanca (tipos, formatos, rangos, decimales, longitud) | `/api/transfer` |
| XSS | El frontend usa `textContent` (nunca `innerHTML`) y la CSP bloquea scripts inline | `app.js`, `helmet` |
| Clickjacking y otras | Cabeceras de `helmet` (CSP, `frame-ancestors 'none'`, etc.) | `helmet()` |
| Filtración de información | Errores genéricos, sin stack traces; `Cache-Control: no-store` en la API | middlewares |
| Falta de trazabilidad | Registro de eventos en `security.log` (login fallido, bloqueos, accesos denegados, transferencias, CSRF) sin contraseñas | `log()` |

> **Importante:** que el frontend no muestre algo no es una medida de seguridad. Todas las comprobaciones críticas se hacen en el servidor.

## Pruebas realizadas

`npm test` ejecuta pruebas automáticas contra el servidor:

- Contraseña incorrecta, usuario inexistente y login con objetos en lugar de texto son rechazados
- Sin sesión no se accede a ninguna cuenta
- Ana no puede ver cuenta ni movimientos de Marcos, ni transferir desde su cuenta
- Transferencias rechazadas por: falta de token CSRF, importe negativo, importe como texto, más de 2 decimales, concepto con caracteres peligrosos, cuenta destino con formato inválido y saldo insuficiente
- Una transferencia válida actualiza el saldo correctamente
- Tras 5 intentos fallidos, ni la contraseña correcta permite entrar
- Tras cerrar sesión, la sesión deja de ser válida

*(Pegá acá una captura del resultado de `npm test` y del `security.log`.)*

## Limitaciones (a propósito, por ser una demo)

- Los datos viven en memoria: se reinician al apagar el servidor.
- Las contraseñas de demostración están en el código; en un sistema real irían en una base de datos y nunca en el repositorio.
- No hay HTTPS local; en producción habría que usarlo y activar `NODE_ENV=production`.
- No hay autenticación de dos factores, recuperación de contraseña ni persistencia de sesiones en un almacén externo.
- El bloqueo por intentos se guarda en memoria y no está pensado para varios servidores.






