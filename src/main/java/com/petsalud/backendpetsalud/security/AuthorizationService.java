package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.repository.CitaRepository;
import com.petsalud.backendpetsalud.repository.ExpedienteMedicoRepository;
import com.petsalud.backendpetsalud.repository.MascotaRepository;
import com.petsalud.backendpetsalud.repository.NotificacionRepository;
import com.petsalud.backendpetsalud.repository.RecompensaRepository;
import com.petsalud.backendpetsalud.repository.VentaRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Reglas de propiedad de recursos usadas en @PreAuthorize (ej: @authz.esDuenoMascota(#id)).
 * Previene IDOR (Insecure Direct Object Reference): un CLIENTE solo accede a SUS datos.
 */
@Component("authz")
public class AuthorizationService {

    private final MascotaRepository mascotaRepository;
    private final CitaRepository citaRepository;
    private final ExpedienteMedicoRepository expedienteRepository;
    private final VentaRepository ventaRepository;
    private final RecompensaRepository recompensaRepository;
    private final NotificacionRepository notificacionRepository;

    public AuthorizationService(MascotaRepository mascotaRepository, CitaRepository citaRepository,
                                ExpedienteMedicoRepository expedienteRepository, VentaRepository ventaRepository,
                                RecompensaRepository recompensaRepository,
                                NotificacionRepository notificacionRepository) {
        this.mascotaRepository = mascotaRepository;
        this.citaRepository = citaRepository;
        this.expedienteRepository = expedienteRepository;
        this.ventaRepository = ventaRepository;
        this.recompensaRepository = recompensaRepository;
        this.notificacionRepository = notificacionRepository;
    }

    private Optional<UsuarioDetails> actual() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UsuarioDetails detalles) {
            return Optional.of(detalles);
        }
        return Optional.empty();
    }

    private boolean esMismo(Usuario usuario) {
        return usuario != null && actual().map(u -> u.getId().equals(usuario.getId())).orElse(false);
    }

    public boolean esStaff() {
        return actual().map(u -> u.getRol() == Rol.EMPLEADO || u.getRol() == Rol.GERENTE).orElse(false);
    }

    public boolean esUsuario(Long usuarioId) {
        return usuarioId != null && actual().map(u -> u.getId().equals(usuarioId)).orElse(false);
    }

    public boolean esDuenoMascota(Long mascotaId) {
        return mascotaId != null && mascotaRepository.findById(mascotaId)
                .map(m -> esMismo(m.getPropietario())).orElse(false);
    }

    public boolean esDuenoCita(Long citaId) {
        return citaId != null && citaRepository.findById(citaId)
                .map(c -> c.getMascota() != null && esMismo(c.getMascota().getPropietario())).orElse(false);
    }

    public boolean esDuenoExpediente(Long expedienteId) {
        return expedienteId != null && expedienteRepository.findById(expedienteId)
                .map(e -> e.getMascota() != null && esMismo(e.getMascota().getPropietario())).orElse(false);
    }

    public boolean esDuenoVenta(Long ventaId) {
        return ventaId != null && ventaRepository.findById(ventaId).map(v -> esMismo(v.getUsuario())).orElse(false);
    }

    public boolean esDuenoRecompensa(Long recompensaId) {
        return recompensaId != null && recompensaRepository.findById(recompensaId)
                .map(r -> esMismo(r.getUsuario())).orElse(false);
    }

    public boolean esDuenoNotificacion(Long notificacionId) {
        return notificacionId != null && notificacionRepository.findById(notificacionId)
                .map(n -> esMismo(n.getUsuario())).orElse(false);
    }
}
