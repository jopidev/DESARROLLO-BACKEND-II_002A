package com.petsalud.backendpetsalud.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Monitoreo basico de actividades sospechosas.
 * - Registra eventos de seguridad en el logger SECURITY_AUDIT (archivo logs/security-audit.log).
 * - Mantiene los ultimos eventos en memoria para consulta del GERENTE (/api/auditoria).
 * - Genera una alerta ACTIVIDAD_SOSPECHOSA cuando una IP acumula muchos fallos en poco tiempo.
 */
@Service
public class SecurityAuditService {

    private static final Logger AUDIT = LoggerFactory.getLogger("SECURITY_AUDIT");
    private static final int MAX_EVENTOS = 500;
    private static final int UMBRAL_FALLOS_IP = 10;
    private static final Duration VENTANA = Duration.ofMinutes(5);
    private static final Set<TipoEventoSeguridad> TIPOS_FALLO = EnumSet.of(
            TipoEventoSeguridad.LOGIN_FALLIDO, TipoEventoSeguridad.TOKEN_INVALIDO,
            TipoEventoSeguridad.ACCESO_DENEGADO, TipoEventoSeguridad.ACCESO_NO_AUTENTICADO,
            TipoEventoSeguridad.CUENTA_BLOQUEADA);

    private final Deque<EventoSeguridad> eventos = new ArrayDeque<>();
    private final Map<String, Deque<Instant>> fallosPorIp = new ConcurrentHashMap<>();

    public void registrar(TipoEventoSeguridad tipo, String usuario, String ip, String ruta, String detalle) {
        EventoSeguridad evento = new EventoSeguridad(Instant.now(), tipo, limpiar(usuario), limpiar(ip),
                limpiar(ruta), limpiar(detalle));
        synchronized (eventos) {
            eventos.addFirst(evento);
            while (eventos.size() > MAX_EVENTOS) {
                eventos.removeLast();
            }
        }
        if (tipo == TipoEventoSeguridad.LOGIN_EXITOSO) {
            AUDIT.info("{} usuario={} ip={} ruta={} detalle={}", tipo, evento.usuario(), evento.ip(), evento.ruta(), evento.detalle());
        } else {
            AUDIT.warn("{} usuario={} ip={} ruta={} detalle={}", tipo, evento.usuario(), evento.ip(), evento.ruta(), evento.detalle());
        }
        if (TIPOS_FALLO.contains(tipo) && ip != null) {
            evaluarActividadSospechosa(evento.ip());
        }
    }

    private void evaluarActividadSospechosa(String ip) {
        Instant ahora = Instant.now();
        Deque<Instant> marcas = fallosPorIp.computeIfAbsent(ip, k -> new ArrayDeque<>());
        boolean alerta;
        synchronized (marcas) {
            marcas.addLast(ahora);
            while (!marcas.isEmpty() && marcas.peekFirst().isBefore(ahora.minus(VENTANA))) {
                marcas.removeFirst();
            }
            alerta = marcas.size() == UMBRAL_FALLOS_IP;
        }
        if (alerta) {
            registrar(TipoEventoSeguridad.ACTIVIDAD_SOSPECHOSA, null, null, null,
                    UMBRAL_FALLOS_IP + " fallos de seguridad en " + VENTANA.toMinutes() + " min desde ip=" + ip);
        }
    }

    public List<EventoSeguridad> ultimosEventos(int limite) {
        synchronized (eventos) {
            return new ArrayList<>(eventos).subList(0, Math.min(limite, eventos.size()));
        }
    }

    public Map<TipoEventoSeguridad, Long> resumen() {
        Map<TipoEventoSeguridad, Long> conteo = new EnumMap<>(TipoEventoSeguridad.class);
        synchronized (eventos) {
            for (EventoSeguridad e : eventos) {
                conteo.merge(e.tipo(), 1L, Long::sum);
            }
        }
        return conteo;
    }

    /** Evita inyeccion de logs (CRLF) y limita el largo. */
    private static String limpiar(String valor) {
        if (valor == null) {
            return "-";
        }
        String limpio = valor.replaceAll("[\\r\\n\\t]", "_");
        return limpio.length() > 200 ? limpio.substring(0, 200) : limpio;
    }
}
