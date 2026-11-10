package com.petsalud.backendpetsalud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.petsalud.backendpetsalud.audit.SecurityAuditService;
import com.petsalud.backendpetsalud.audit.TipoEventoSeguridad;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** Respuesta 401 en JSON (sin redirecciones ni paginas HTML). */
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final SecurityAuditService auditoria;

    public RestAuthenticationEntryPoint(ObjectMapper objectMapper, SecurityAuditService auditoria) {
        this.objectMapper = objectMapper;
        this.auditoria = auditoria;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        boolean tokenInvalido = request.getAttribute(JwtAuthenticationFilter.ATRIBUTO_ERROR_JWT) != null;
        if (!tokenInvalido) {
            auditoria.registrar(TipoEventoSeguridad.ACCESO_NO_AUTENTICADO, null, request.getRemoteAddr(),
                    request.getRequestURI(), "sin token");
        }
        Map<String, Object> cuerpo = new LinkedHashMap<>();
        cuerpo.put("fecha", Instant.now().toString());
        cuerpo.put("status", 401);
        cuerpo.put("error", "No autorizado");
        cuerpo.put("mensaje", tokenInvalido ? "Token invalido o expirado" : "Se requiere autenticacion");
        cuerpo.put("ruta", request.getRequestURI());
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(), cuerpo);
    }
}
