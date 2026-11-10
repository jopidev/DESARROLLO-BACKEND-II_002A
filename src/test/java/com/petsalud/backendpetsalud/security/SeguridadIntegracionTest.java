package com.petsalud.backendpetsalud.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.petsalud.backendpetsalud.repository.MascotaRepository;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Pruebas de seguridad de extremo a extremo (MockMvc + cadena completa de filtros de Spring Security).
 * Usuarios de prueba creados por DataInitializer (perfil test).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SeguridadIntegracionTest {

    private static final String GERENTE = "gerente@petsalud.cl";
    private static final String EMPLEADO = "empleado@petsalud.cl";
    private static final String CLIENTE = "cliente@petsalud.cl";
    private static final String CLIENTE2 = "cliente2@petsalud.cl";

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper om;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private UsuarioDetailsService usuarioDetailsService;
    @Autowired private UsuarioRepository usuarioRepository;
    @Autowired private MascotaRepository mascotaRepository;

    // ----------------------------------------------------------------- utilidades

    private String json(Object o) throws Exception {
        return om.writeValueAsString(o);
    }

    private String token(String email) throws Exception {
        String pw = switch (email) {
            case GERENTE -> "Gerente#2025";
            case EMPLEADO -> "Empleado#2025";
            default -> "Cliente#2025";
        };
        MvcResult r = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", email, "password", pw))))
                .andExpect(status().isOk()).andReturn();
        return om.readTree(r.getResponse().getContentAsString()).get("token").asText();
    }

    private String bearer(String email) throws Exception {
        return "Bearer " + token(email);
    }

    private Long idUsuario(String email) {
        return usuarioRepository.findByEmail(email).orElseThrow().getId();
    }

    // ======================================================= 1. AUTENTICACION / JWT

    @Test
    @DisplayName("JWT-01 Login valido entrega JWT firmado, tipo Bearer y sin cookie de sesion")
    void loginValidoEntregaToken() throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", GERENTE, "password", "Gerente#2025"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tipo").value("Bearer"))
                .andExpect(jsonPath("$.rol").value("GERENTE"))
                .andExpect(jsonPath("$.expiraEnSegundos").value(900))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andReturn();
        String token = om.readTree(r.getResponse().getContentAsString()).get("token").asText();
        assertThat(token.split("\\.")).hasSize(3);
        assertThat(jwtUtil.validarToken(token).getSubject()).isEqualTo(GERENTE);
        assertThat(r.getRequest().getSession(false)).isNull(); // stateless
    }

    @Test
    @DisplayName("JWT-02 Credenciales invalidas y usuario inexistente responden igual (401 generico)")
    void credencialesInvalidas() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", EMPLEADO, "password", "incorrecta"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensaje").value("Credenciales invalidas"))
                .andExpect(jsonPath("$.token").doesNotExist());
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", "noexiste@petsalud.cl", "password", "x"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensaje").value("Credenciales invalidas"));
    }

    @Test
    @DisplayName("JWT-03 Endpoint protegido sin token responde 401")
    void sinToken() throws Exception {
        mvc.perform(get("/api/productos")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("JWT-04 Token manipulado (rol cambiado en el payload) es rechazado")
    void tokenManipulado() throws Exception {
        String[] partes = token(CLIENTE).split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(partes[1]), StandardCharsets.UTF_8)
                .replace("ROLE_CLIENTE", "ROLE_GERENTE");
        String falso = partes[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + partes[2];
        mvc.perform(get("/api/usuarios").header(HttpHeaders.AUTHORIZATION, "Bearer " + falso))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensaje").value("Token invalido o expirado"));
    }

    @Test
    @DisplayName("JWT-05 Token expirado es rechazado")
    void tokenExpirado() throws Exception {
        String expirado = jwtUtil.generarToken(usuarioDetailsService.loadUserByUsername(GERENTE), -120_000);
        mvc.perform(get("/api/productos").header(HttpHeaders.AUTHORIZATION, "Bearer " + expirado))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("JWT-06 Token firmado con otra clave es rechazado")
    void tokenOtraClave() throws Exception {
        String ajeno = Jwts.builder().subject(GERENTE).issuer("petsalud-backend")
                .expiration(new Date(System.currentTimeMillis() + 600_000))
                .signWith(Jwts.SIG.HS256.key().build()).compact();
        mvc.perform(get("/api/usuarios").header(HttpHeaders.AUTHORIZATION, "Bearer " + ajeno))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("JWT-07 Token sin firma (alg=none) es rechazado")
    void tokenSinFirma() throws Exception {
        String sinFirma = Jwts.builder().subject(GERENTE).issuer("petsalud-backend")
                .expiration(new Date(System.currentTimeMillis() + 600_000)).compact();
        mvc.perform(get("/api/usuarios").header(HttpHeaders.AUTHORIZATION, "Bearer " + sinFirma))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("JWT-08 Fuerza bruta: tras 5 intentos fallidos la cuenta se bloquea (429)")
    void bloqueoPorFuerzaBruta() throws Exception {
        for (int i = 0; i < LoginAttemptService.MAX_INTENTOS; i++) {
            mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                            .content(json(Map.of("email", "bloqueo@petsalud.cl", "password", "mala" + i))))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", "bloqueo@petsalud.cl", "password", "Bloqueo#2025"))))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.token").doesNotExist());
    }

    @Test
    @DisplayName("JWT-09 Registro publico fuerza rol CLIENTE, guarda hash BCrypt y no expone password")
    void registroFuerzaRolCliente() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", "nuevo@petsalud.cl", "password", "Segura#2025",
                                "nombre", "Nuevo", "rol", "GERENTE"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.rol").value("CLIENTE"))
                .andExpect(jsonPath("$.password").doesNotExist());
        String hash = usuarioRepository.findByEmail("nuevo@petsalud.cl").orElseThrow().getPassword();
        assertThat(hash).startsWith("$2").isNotEqualTo("Segura#2025");
    }

    @Test
    @DisplayName("JWT-10 Registro con password debil es rechazado (400)")
    void passwordDebil() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", "debil@petsalud.cl", "password", "123456", "nombre", "Debil"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errores.password").exists());
    }

    // ======================================================= 2. AUTORIZACION POR ROLES

    @Test
    @DisplayName("ROL-01 Listar usuarios: solo GERENTE")
    void listarUsuariosSoloGerente() throws Exception {
        mvc.perform(get("/api/usuarios").header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE))).andExpect(status().isForbidden());
        mvc.perform(get("/api/usuarios").header(HttpHeaders.AUTHORIZATION, bearer(EMPLEADO))).andExpect(status().isForbidden());
        mvc.perform(get("/api/usuarios").header(HttpHeaders.AUTHORIZATION, bearer(GERENTE)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].password").doesNotExist());
    }

    @Test
    @DisplayName("ROL-02 Productos: CLIENTE lee, EMPLEADO crea, solo GERENTE elimina")
    void productosPorRol() throws Exception {
        String nuevo = json(Map.of("nombre", "Shampoo Test " + System.nanoTime(), "descripcion", "Hipoalergenico",
                "precio", 5990, "stock", 10, "categoria", "Higiene"));
        mvc.perform(get("/api/productos").header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE))).andExpect(status().isOk());
        mvc.perform(post("/api/productos").header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE))
                .contentType(MediaType.APPLICATION_JSON).content(nuevo)).andExpect(status().isForbidden());
        MvcResult creado = mvc.perform(post("/api/productos").header(HttpHeaders.AUTHORIZATION, bearer(EMPLEADO))
                .contentType(MediaType.APPLICATION_JSON).content(nuevo)).andExpect(status().isOk()).andReturn();
        long id = om.readTree(creado.getResponse().getContentAsString()).get("id").asLong();
        mvc.perform(delete("/api/productos/" + id).header(HttpHeaders.AUTHORIZATION, bearer(EMPLEADO))).andExpect(status().isForbidden());
        mvc.perform(delete("/api/productos/" + id).header(HttpHeaders.AUTHORIZATION, bearer(GERENTE))).andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("ROL-03 Stock bajo (inventario) solo para personal")
    void stockBajoSoloPersonal() throws Exception {
        mvc.perform(get("/api/productos/stock-bajo").param("cantidad", "5").header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE)))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/productos/stock-bajo").param("cantidad", "5").header(HttpHeaders.AUTHORIZATION, bearer(EMPLEADO)))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))));
    }

    @Test
    @DisplayName("ROL-04 Reporte de ventas y auditoria: solo GERENTE")
    void reportesSoloGerente() throws Exception {
        mvc.perform(get("/api/ventas").header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE))).andExpect(status().isForbidden());
        mvc.perform(get("/api/ventas").header(HttpHeaders.AUTHORIZATION, bearer(EMPLEADO))).andExpect(status().isForbidden());
        mvc.perform(get("/api/ventas").header(HttpHeaders.AUTHORIZATION, bearer(GERENTE))).andExpect(status().isOk());
        mvc.perform(get("/api/auditoria/eventos").header(HttpHeaders.AUTHORIZATION, bearer(EMPLEADO))).andExpect(status().isForbidden());
        mvc.perform(get("/api/auditoria/eventos").header(HttpHeaders.AUTHORIZATION, bearer(GERENTE)))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))));
    }

    @Test
    @DisplayName("ROL-05 Expedientes medicos: CLIENTE no puede crear registros clinicos")
    void expedientesSoloPersonal() throws Exception {
        Long mascotaId = mascotaRepository.findByPropietarioId(idUsuario(CLIENTE)).get(0).getId();
        String registro = json(Map.of("descripcion", "Control anual", "diagnostico", "Sano"));
        mvc.perform(post("/api/expedientes").param("mascotaId", mascotaId.toString())
                        .param("veterinarioId", idUsuario(EMPLEADO).toString())
                        .header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE))
                        .contentType(MediaType.APPLICATION_JSON).content(registro))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/expedientes").param("mascotaId", mascotaId.toString())
                        .param("veterinarioId", idUsuario(EMPLEADO).toString())
                        .header(HttpHeaders.AUTHORIZATION, bearer(EMPLEADO))
                        .contentType(MediaType.APPLICATION_JSON).content(registro))
                .andExpect(status().isOk());
        // El duenio si puede leer el historial de su mascota
        mvc.perform(get("/api/expedientes/mascota/" + mascotaId).header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE)))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))));
    }

    @Test
    @DisplayName("ROL-06 IDOR: un CLIENTE no accede a datos de otro cliente")
    void controlDePropiedad() throws Exception {
        Long propio = idUsuario(CLIENTE);
        Long ajeno = idUsuario(CLIENTE2);
        Long mascotaAjena = mascotaRepository.findByPropietarioId(ajeno).get(0).getId();
        String tokenCliente = bearer(CLIENTE);

        mvc.perform(get("/api/usuarios/" + ajeno).header(HttpHeaders.AUTHORIZATION, tokenCliente)).andExpect(status().isForbidden());
        mvc.perform(get("/api/mascotas/propietario/" + ajeno).header(HttpHeaders.AUTHORIZATION, tokenCliente)).andExpect(status().isForbidden());
        mvc.perform(get("/api/mascotas/" + mascotaAjena).header(HttpHeaders.AUTHORIZATION, tokenCliente)).andExpect(status().isForbidden());
        mvc.perform(get("/api/expedientes/mascota/" + mascotaAjena).header(HttpHeaders.AUTHORIZATION, tokenCliente)).andExpect(status().isForbidden());
        mvc.perform(get("/api/ventas/usuario/" + ajeno).header(HttpHeaders.AUTHORIZATION, tokenCliente)).andExpect(status().isForbidden());

        mvc.perform(get("/api/usuarios/" + propio).header(HttpHeaders.AUTHORIZATION, tokenCliente)).andExpect(status().isOk());
        mvc.perform(get("/api/mascotas/propietario/" + propio).header(HttpHeaders.AUTHORIZATION, tokenCliente)).andExpect(status().isOk());
        mvc.perform(get("/api/mascotas/" + mascotaAjena).header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE2))).andExpect(status().isOk());
        mvc.perform(get("/api/mascotas/" + mascotaAjena).header(HttpHeaders.AUTHORIZATION, bearer(EMPLEADO))).andExpect(status().isOk());
    }

    @Test
    @DisplayName("ROL-07 Un CLIENTE no puede crear usuarios ni escalar privilegios")
    void sinEscaladaDePrivilegios() throws Exception {
        String empleado = json(Map.of("email", "intruso@petsalud.cl", "password", "Intruso#2025",
                "nombre", "Intruso", "rol", "GERENTE"));
        mvc.perform(post("/api/usuarios").header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE))
                .contentType(MediaType.APPLICATION_JSON).content(empleado)).andExpect(status().isForbidden());
        assertThat(usuarioRepository.findByEmail("intruso@petsalud.cl")).isEmpty();
    }

    // ======================================================= 3. XSS

    @Test
    @DisplayName("XSS-01 Script en registro es rechazado (400)")
    void xssEnRegistro() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", "xss@petsalud.cl", "password", "Segura#2025",
                                "nombre", "<script>alert('xss')</script>"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errores.nombre").exists());
        assertThat(usuarioRepository.findByEmail("xss@petsalud.cl")).isEmpty();
    }

    @Test
    @DisplayName("XSS-02 Payload con manejador de eventos en producto es rechazado (400)")
    void xssEnProducto() throws Exception {
        mvc.perform(post("/api/productos").header(HttpHeaders.AUTHORIZATION, bearer(EMPLEADO))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("nombre", "Juguete", "descripcion", "<img src=x onerror=alert(1)>",
                                "precio", 1000, "stock", 1, "categoria", "Juguetes"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("XSS-03 Script en parametro de consulta (motivo de cita) es rechazado (400)")
    void xssEnParametro() throws Exception {
        Long mascotaId = mascotaRepository.findByPropietarioId(idUsuario(CLIENTE)).get(0).getId();
        mvc.perform(post("/api/citas").header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE))
                        .param("mascotaId", mascotaId.toString())
                        .param("veterinarioId", idUsuario(EMPLEADO).toString())
                        .param("fechaHora", LocalDateTime.now().plusDays(3).withNano(0).toString())
                        .param("motivo", "<script>document.location='http://evil.com'</script>"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("XSS-04 Cabeceras de seguridad presentes (CSP, nosniff, X-Frame-Options, Referrer-Policy)")
    void cabecerasDeSeguridad() throws Exception {
        mvc.perform(get("/api/productos").header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE)))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, containsString("application/json")));
    }

    // ======================================================= 4. SQL INJECTION

    @Test
    @DisplayName("SQLI-01 Inyeccion en login no autentica")
    void sqliEnLogin() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", "' OR '1'='1' --", "password", "x"))))
                .andExpect(status().is4xxClientError()).andExpect(jsonPath("$.token").doesNotExist());
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", GERENTE, "password", "' OR '1'='1"))))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.token").doesNotExist());
    }

    @Test
    @DisplayName("SQLI-02 Inyeccion en filtro de categoria se trata como texto literal (0 resultados)")
    void sqliEnBusqueda() throws Exception {
        String token = bearer(CLIENTE);
        mvc.perform(get("/api/productos/categoria").param("categoria", "Alimentos").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))));
        mvc.perform(get("/api/productos/categoria").param("categoria", "' OR '1'='1' --").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));
        mvc.perform(get("/api/productos/categoria").param("categoria", "x'; DROP TABLE productos; --").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));
        // La tabla sigue intacta
        mvc.perform(get("/api/productos").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(2))));
    }

    @Test
    @DisplayName("SQLI-03 Inyeccion en path variable numerica es rechazada (400)")
    void sqliEnPath() throws Exception {
        mvc.perform(get("/api/productos/{id}", "1 OR 1=1").header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE)))
                .andExpect(status().isBadRequest());
    }

    // ======================================================= 5. CSRF / CORS

    @Test
    @DisplayName("CSRF-01 Peticion cruzada con cookie pero sin JWT no se ejecuta (401)")
    void csrfSinToken() throws Exception {
        mvc.perform(post("/api/productos").cookie(new Cookie("JSESSIONID", "robada"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("nombre", "CSRF", "precio", 1, "stock", 1))))
                .andExpect(status().isUnauthorized());
        mvc.perform(delete("/api/productos/1").cookie(new Cookie("JSESSIONID", "robada")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("CSRF-02 Origen no permitido es bloqueado por CORS aun con token valido (403)")
    void corsOrigenNoPermitido() throws Exception {
        mvc.perform(get("/api/productos").header(HttpHeaders.ORIGIN, "https://sitio-malicioso.com")
                        .header(HttpHeaders.AUTHORIZATION, bearer(CLIENTE)))
                .andExpect(status().isForbidden());
        mvc.perform(options("/api/productos").header(HttpHeaders.ORIGIN, "https://sitio-malicioso.com")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("CSRF-03 Origen permitido (frontend oficial) supera el preflight CORS")
    void corsOrigenPermitido() throws Exception {
        mvc.perform(options("/api/productos").header(HttpHeaders.ORIGIN, "http://localhost:4200")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:4200"));
    }

    // ======================================================= 6. FUGA DE INFORMACION

    @Test
    @DisplayName("INF-01 Errores no exponen trazas internas")
    void erroresSinTrazas() throws Exception {
        MvcResult r = mvc.perform(post("/api/productos").header(HttpHeaders.AUTHORIZATION, bearer(EMPLEADO))
                        .contentType(MediaType.APPLICATION_JSON).content("{ json roto"))
                .andExpect(status().isBadRequest()).andReturn();
        JsonNode body = om.readTree(r.getResponse().getContentAsString());
        assertThat(body.has("trace")).isFalse();
        assertThat(body.toString()).doesNotContain("Exception").doesNotContain("at com.");
    }
}
