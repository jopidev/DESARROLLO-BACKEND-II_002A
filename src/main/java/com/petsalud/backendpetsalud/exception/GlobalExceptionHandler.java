package com.petsalud.backendpetsalud.exception;

import com.petsalud.backendpetsalud.audit.SecurityAuditService;
import com.petsalud.backendpetsalud.audit.TipoEventoSeguridad;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Manejo centralizado de errores: respuestas uniformes sin trazas internas (evita fuga de informacion)
 * y registro de entradas rechazadas para el monitoreo de seguridad.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final SecurityAuditService auditoria;

    public GlobalExceptionHandler(SecurityAuditService auditoria) {
        this.auditoria = auditoria;
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> validacion(MethodArgumentNotValidException ex, HttpServletRequest req) {
        Map<String, String> errores = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors()
                .forEach(e -> errores.putIfAbsent(e.getField(), e.getDefaultMessage()));
        registrarRechazo(req, "campos=" + errores.keySet());
        Map<String, Object> cuerpo = cuerpo(HttpStatus.BAD_REQUEST, "Datos de entrada invalidos", req);
        cuerpo.put("errores", errores);
        return ResponseEntity.badRequest().body(cuerpo);
    }

    @ExceptionHandler({HandlerMethodValidationException.class, ConstraintViolationException.class})
    public ResponseEntity<Map<String, Object>> validacionParametros(Exception ex, HttpServletRequest req) {
        registrarRechazo(req, ex.getClass().getSimpleName());
        return ResponseEntity.badRequest().body(cuerpo(HttpStatus.BAD_REQUEST, "Parametros invalidos", req));
    }

    @ExceptionHandler(TransactionSystemException.class)
    public ResponseEntity<Map<String, Object>> transaccion(TransactionSystemException ex, HttpServletRequest req) {
        if (ex.getRootCause() instanceof ConstraintViolationException) {
            registrarRechazo(req, "validacion JPA");
            return ResponseEntity.badRequest().body(cuerpo(HttpStatus.BAD_REQUEST, "Datos de entrada invalidos", req));
        }
        log.error("Error de transaccion", ex);
        return ResponseEntity.internalServerError().body(cuerpo(HttpStatus.INTERNAL_SERVER_ERROR, "Error interno", req));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> negocio(IllegalArgumentException ex, HttpServletRequest req) {
        // Los mensajes de IllegalArgumentException son definidos por la aplicacion (no exponen internos)
        return ResponseEntity.badRequest().body(cuerpo(HttpStatus.BAD_REQUEST, ex.getMessage(), req));
    }

    @ExceptionHandler({DateTimeParseException.class, MissingServletRequestParameterException.class,
            HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<Map<String, Object>> formato(Exception ex, HttpServletRequest req) {
        registrarRechazo(req, ex.getClass().getSimpleName());
        return ResponseEntity.badRequest().body(cuerpo(HttpStatus.BAD_REQUEST, "Formato de solicitud invalido", req));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> integridad(DataIntegrityViolationException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(cuerpo(HttpStatus.CONFLICT, "Conflicto de datos", req));
    }

    /** Denegaciones de @PreAuthorize (incluye AuthorizationDeniedException). */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> accesoDenegado(AccessDeniedException ex, HttpServletRequest req) {
        String usuario = req.getUserPrincipal() != null ? req.getUserPrincipal().getName() : null;
        auditoria.registrar(TipoEventoSeguridad.ACCESO_DENEGADO, usuario, req.getRemoteAddr(),
                req.getRequestURI(), req.getMethod());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(cuerpo(HttpStatus.FORBIDDEN, "No tiene permisos para este recurso", req));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> generico(Exception ex, HttpServletRequest req) {
        if (ex instanceof ErrorResponse errorResponse) {
            // 404, 405, 415, etc. generados por Spring MVC
            HttpStatusCode status = errorResponse.getStatusCode();
            Map<String, Object> cuerpo = new LinkedHashMap<>();
            cuerpo.put("fecha", Instant.now().toString());
            cuerpo.put("status", status.value());
            cuerpo.put("mensaje", "Solicitud no valida");
            cuerpo.put("ruta", req.getRequestURI());
            return ResponseEntity.status(status).body(cuerpo);
        }
        log.error("Error no controlado en {}", req.getRequestURI(), ex);
        return ResponseEntity.internalServerError()
                .body(cuerpo(HttpStatus.INTERNAL_SERVER_ERROR, "Error interno del servidor", req));
    }

    private void registrarRechazo(HttpServletRequest req, String detalle) {
        String usuario = req.getUserPrincipal() != null ? req.getUserPrincipal().getName() : null;
        auditoria.registrar(TipoEventoSeguridad.ENTRADA_RECHAZADA, usuario, req.getRemoteAddr(), req.getRequestURI(), detalle);
    }

    private Map<String, Object> cuerpo(HttpStatus status, String mensaje, HttpServletRequest req) {
        Map<String, Object> cuerpo = new LinkedHashMap<>();
        cuerpo.put("fecha", Instant.now().toString());
        cuerpo.put("status", status.value());
        cuerpo.put("error", status.getReasonPhrase());
        cuerpo.put("mensaje", mensaje);
        cuerpo.put("ruta", req.getRequestURI());
        return cuerpo;
    }
}
