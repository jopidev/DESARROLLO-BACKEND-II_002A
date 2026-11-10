package com.petsalud.backendpetsalud.audit;

import java.time.Instant;

public record EventoSeguridad(Instant fecha, TipoEventoSeguridad tipo, String usuario, String ip,
                              String ruta, String detalle) {
}
