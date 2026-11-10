package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.audit.SecurityAuditService;
import com.petsalud.backendpetsalud.audit.TipoEventoSeguridad;
import com.petsalud.backendpetsalud.dto.AuthResponse;
import com.petsalud.backendpetsalud.dto.LoginRequest;
import com.petsalud.backendpetsalud.dto.RegistroRequest;
import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.security.JwtUtil;
import com.petsalud.backendpetsalud.security.LoginAttemptService;
import com.petsalud.backendpetsalud.security.UsuarioDetails;
import com.petsalud.backendpetsalud.service.UsuarioService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UsuarioService usuarioService;
    private final LoginAttemptService loginAttemptService;
    private final SecurityAuditService auditoria;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil, UsuarioService usuarioService,
                          LoginAttemptService loginAttemptService, SecurityAuditService auditoria) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.usuarioService = usuarioService;
        this.loginAttemptService = loginAttemptService;
        this.auditoria = auditoria;
    }

    /** Autentica con email/password y entrega un JWT de corta duracion. */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        String email = request.email().trim().toLowerCase();
        String ip = http.getRemoteAddr();

        if (loginAttemptService.estaBloqueado(email)) {
            auditoria.registrar(TipoEventoSeguridad.CUENTA_BLOQUEADA, email, ip, http.getRequestURI(),
                    "intento durante bloqueo");
            return error(HttpStatus.TOO_MANY_REQUESTS, "Cuenta bloqueada temporalmente",
                    "Demasiados intentos fallidos. Intente nuevamente en "
                            + LoginAttemptService.DURACION_BLOQUEO.toMinutes() + " minutos");
        }
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, request.password()));
            UsuarioDetails usuario = (UsuarioDetails) auth.getPrincipal();
            loginAttemptService.loginExitoso(email);
            auditoria.registrar(TipoEventoSeguridad.LOGIN_EXITOSO, email, ip, http.getRequestURI(), usuario.getRol().name());
            String token = jwtUtil.generarToken(usuario);
            return ResponseEntity.ok(new AuthResponse(token, "Bearer", jwtUtil.getExpiracionMs() / 1000,
                    usuario.getUsername(), usuario.getRol().name()));
        } catch (AuthenticationException e) {
            boolean bloqueada = loginAttemptService.loginFallido(email);
            auditoria.registrar(bloqueada ? TipoEventoSeguridad.CUENTA_BLOQUEADA : TipoEventoSeguridad.LOGIN_FALLIDO,
                    email, ip, http.getRequestURI(), e.getClass().getSimpleName());
            // Mensaje generico: no revela si el usuario existe (evita enumeracion de cuentas)
            return error(HttpStatus.UNAUTHORIZED, "No autorizado", "Credenciales invalidas");
        }
    }

    /** Registro publico de clientes. El rol se fuerza a CLIENTE (no se acepta desde el cliente). */
    @PostMapping("/registro")
    public ResponseEntity<Usuario> registro(@Valid @RequestBody RegistroRequest request) {
        Usuario usuario = Usuario.builder()
                .email(request.email())
                .password(request.password())
                .nombre(request.nombre())
                .apellido(request.apellido())
                .telefono(request.telefono())
                .direccion(request.direccion())
                .rol(Rol.CLIENTE)
                .build();
        return ResponseEntity.status(HttpStatus.CREATED).body(usuarioService.registrarUsuario(usuario));
    }

    private ResponseEntity<Map<String, Object>> error(HttpStatus status, String error, String mensaje) {
        Map<String, Object> cuerpo = new LinkedHashMap<>();
        cuerpo.put("status", status.value());
        cuerpo.put("error", error);
        cuerpo.put("mensaje", mensaje);
        return ResponseEntity.status(status).body(cuerpo);
    }
}
