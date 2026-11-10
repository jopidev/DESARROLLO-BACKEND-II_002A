package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.audit.EventoSeguridad;
import com.petsalud.backendpetsalud.audit.SecurityAuditService;
import com.petsalud.backendpetsalud.audit.TipoEventoSeguridad;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Monitoreo basico de actividades sospechosas (solo GERENTE). */
@RestController
@RequestMapping("/api/auditoria")
@PreAuthorize("hasRole('GERENTE')")
public class AuditoriaController {

    private final SecurityAuditService auditoria;

    public AuditoriaController(SecurityAuditService auditoria) {
        this.auditoria = auditoria;
    }

    @GetMapping("/eventos")
    public ResponseEntity<List<EventoSeguridad>> eventos(@RequestParam(defaultValue = "100") int limite) {
        return ResponseEntity.ok(auditoria.ultimosEventos(Math.max(1, Math.min(limite, 500))));
    }

    @GetMapping("/resumen")
    public ResponseEntity<Map<TipoEventoSeguridad, Long>> resumen() {
        return ResponseEntity.ok(auditoria.resumen());
    }
}
