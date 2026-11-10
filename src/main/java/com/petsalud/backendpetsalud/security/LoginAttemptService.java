package com.petsalud.backendpetsalud.security;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Proteccion contra fuerza bruta: bloquea la cuenta 15 minutos tras 5 intentos fallidos consecutivos.
 */
@Service
public class LoginAttemptService {

    public static final int MAX_INTENTOS = 5;
    public static final Duration DURACION_BLOQUEO = Duration.ofMinutes(15);

    private record Intento(int fallos, Instant bloqueadoHasta) {
    }

    private final Map<String, Intento> intentos = new ConcurrentHashMap<>();

    public boolean estaBloqueado(String clave) {
        Intento intento = intentos.get(clave);
        if (intento == null || intento.bloqueadoHasta() == null) {
            return false;
        }
        if (Instant.now().isAfter(intento.bloqueadoHasta())) {
            intentos.remove(clave);
            return false;
        }
        return true;
    }

    /** @return true si con este fallo la cuenta queda bloqueada */
    public boolean loginFallido(String clave) {
        Intento nuevo = intentos.compute(clave, (k, actual) -> {
            int fallos = (actual == null ? 0 : actual.fallos()) + 1;
            Instant hasta = fallos >= MAX_INTENTOS ? Instant.now().plus(DURACION_BLOQUEO) : null;
            return new Intento(fallos, hasta);
        });
        return nuevo.bloqueadoHasta() != null;
    }

    public void loginExitoso(String clave) {
        intentos.remove(clave);
    }
}
