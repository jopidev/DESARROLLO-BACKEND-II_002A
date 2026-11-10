package com.petsalud.backendpetsalud.dto;

import com.petsalud.backendpetsalud.validation.SafeText;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Campos actualizables del perfil. Email, password y rol quedan fuera (evita mass assignment).
 */
public record ActualizarUsuarioRequest(
        @SafeText @Size(max = 60) String nombre,
        @SafeText @Size(max = 60) String apellido,
        @Size(max = 20) @Pattern(regexp = "^[+0-9 ]*$", message = "solo digitos, espacios y '+'") String telefono,
        @SafeText @Size(max = 150) String direccion) {
}
