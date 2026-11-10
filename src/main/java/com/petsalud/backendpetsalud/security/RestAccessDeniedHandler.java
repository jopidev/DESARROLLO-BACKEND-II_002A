package com.petsalud.backendpetsalud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.petsalud.backendpetsalud.audit.SecurityAuditService;
import com.petsalud.backendpetsalud.audit.TipoEventoSeguridad;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** Respuesta 403 en JSON para reglas de autorizacion a nivel de URL. */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;
    private final SecurityAuditService auditoria;

    public RestAccessDeniedHandler(ObjectMapper objectMapper, SecurityAuditService auditoria) {
        this.objectMapper = objectMapper;
        this.auditoria = auditoria;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        String usuario = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : null;
        auditoria.registrar(TipoEventoSeguridad.ACCESO_DENEGADO, usuario, request.getRemoteAddr(),
                request.getRequestURI(), request.getMethod());
        Map<String, Object> cuerpo = new LinkedHashMap<>();
        cuerpo.put("fecha", Instant.now().toString());
        cuerpo.put("status", 403);
        cuerpo.put("error", "Prohibido");
        cuerpo.put("mensaje", "No tiene permisos para este recurso");
        cuerpo.put("ruta", request.getRequestURI());
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(), cuerpo);
    }
}
