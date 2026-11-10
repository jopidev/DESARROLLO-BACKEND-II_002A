# Backend Clínica PetSalud — Seguridad con Spring Security + JWT

Backend REST (Spring Boot 3.3, Java 17) de la Clínica Veterinaria PetSalud, asegurado con **Spring Security 6**, **JWT (JJWT 0.12)**, **BCrypt** y **autorización basada en roles** (CLIENTE, EMPLEADO, GERENTE).

> Actividad sumativa Exp1 S3 — Desarrollo Backend II (PBY2202) · DuocUC

## Ejecución rápida

```bash
# Perfil dev (por defecto): H2 en memoria + usuarios de demostración
./mvnw spring-boot:run          # Windows: mvnw.cmd spring-boot:run

# Pruebas de seguridad automatizadas (28 casos + carga de contexto)
./mvnw test
```

Usuarios de demostración (solo perfiles `dev` y `test`):

| Rol | Email | Contraseña |
|---|---|---|
| GERENTE | gerente@petsalud.cl | Gerente#2025 |
| EMPLEADO | empleado@petsalud.cl | Empleado#2025 |
| CLIENTE | cliente@petsalud.cl | Cliente#2025 |
| CLIENTE | cliente2@petsalud.cl | Cliente#2025 |

### Producción (MySQL)

```bash
export SPRING_PROFILES_ACTIVE=prod
export DB_URL="jdbc:mysql://host:3306/petsalud_db?sslMode=REQUIRED"
export DB_USERNAME=... DB_PASSWORD=...
export JWT_SECRET=$(openssl rand -base64 48)      # >= 256 bits
export CORS_ALLOWED_ORIGINS=https://app.petsalud.cl
./mvnw spring-boot:run
```

Ninguna credencial queda en el repositorio. Nota de migración: los roles anteriores `VETERINARIO`/`ADMIN` pasan a `EMPLEADO`/`GERENTE`.

## Flujo de autenticación

1. `POST /api/auth/login` `{email, password}` → `{token, tipo:"Bearer", expiraEnSegundos:900, rol}`
2. Cada solicitud: cabecera `Authorization: Bearer <token>`
3. `JwtAuthenticationFilter` valida firma HS256, emisor y expiración y carga el usuario en el `SecurityContext`.
4. Reglas por URL en `SecurityConfig` + `@PreAuthorize` por método (rol y propiedad del recurso).

## Matriz de permisos

| Recurso | CLIENTE | EMPLEADO | GERENTE |
|---|---|---|---|
| `POST /api/auth/login`, `/registro` | público | público | público |
| `GET /api/productos`, `/{id}`, `/categoria` | ✔ | ✔ | ✔ |
| `POST/PUT /api/productos`, `GET /stock-bajo` | ✖ | ✔ | ✔ |
| `DELETE /api/productos/{id}` | ✖ | ✖ | ✔ |
| `/api/mascotas/**` | solo las suyas | ✔ (eliminar ✔) | ✔ |
| `POST /api/citas` | solo para su mascota | ✔ | ✔ |
| `PUT /api/citas/{id}/estado`, agenda veterinario, entre fechas | ✖ | ✔ | ✔ |
| `POST /api/expedientes` | ✖ | ✔ | ✔ |
| `GET /api/expedientes/**` | solo sus mascotas | ✔ | ✔ |
| `DELETE /api/expedientes/{id}` | ✖ | ✖ | ✔ |
| `POST /api/ventas` / `GET /usuario/{id}` | solo propias | ✔ | ✔ |
| `GET /api/ventas` (reportes) | ✖ | ✖ | ✔ |
| `POST /api/recompensas`, `/api/notificaciones` | ✖ | ✔ | ✔ |
| `GET` recompensas/notificaciones | solo propias | ✔ | ✔ |
| `GET /api/usuarios/me` | ✔ | ✔ | ✔ |
| `GET /api/usuarios/{id}` | solo el propio | ✔ | ✔ |
| `GET /api/usuarios`, `POST`, `DELETE` | ✖ | ✖ | ✔ |
| `/api/auditoria/**` | ✖ | ✖ | ✔ |

## Controles de seguridad

| Amenaza | Control |
|---|---|
| Acceso no autorizado | JWT firmado (HS256), vida corta 15 min, emisor validado, `alg:none` rechazado, roles + `@PreAuthorize`, control de propiedad (anti‑IDOR) |
| Credenciales | BCrypt costo 12, política de contraseñas, mensaje genérico (sin enumeración), bloqueo 15 min tras 5 fallos |
| SQL Injection | Spring Data JPA (consultas parametrizadas), sin SQL concatenado, tipado fuerte de parámetros |
| XSS | Validación `@SafeText` en entradas, respuestas `application/json`, CSP `default-src 'none'`, `X-Content-Type-Options: nosniff` |
| CSRF | API stateless sin cookies (el JWT viaja en cabecera, el navegador no lo adjunta solo) + CORS restringido |
| Clickjacking / fuga | `X-Frame-Options: DENY`, HSTS, `Referrer-Policy: no-referrer`, errores sin trazas, password `WRITE_ONLY` |
| Monitoreo | `SecurityAuditService` → `logs/security-audit.log`, alerta `ACTIVIDAD_SOSPECHOSA` (≥10 fallos/5 min por IP), `/api/auditoria` |

## Estructura

```
src/main/java/com/petsalud/backendpetsalud
├── audit/        SecurityAuditService, eventos de seguridad
├── config/       DataInitializer (solo dev/test)
├── controller/   AuthController, AuditoriaController + controladores de negocio
├── dto/          LoginRequest, RegistroRequest, AuthResponse, ...
├── entity/       Entidades JPA con validación
├── exception/    GlobalExceptionHandler (errores uniformes, sin trazas)
├── repository/   Spring Data JPA
├── security/     SecurityConfig, JwtUtil, JwtAuthenticationFilter, AuthorizationService (@authz), ...
├── service/
└── validation/   @SafeText (anti‑XSS)
src/test/java/.../security/SeguridadIntegracionTest.java   28 pruebas de seguridad
docs/pruebas-seguridad.http                                  pruebas manuales
```
