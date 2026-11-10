package com.petsalud.backendpetsalud.dto;

import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.validation.SafeText;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Alta de usuarios con rol explicito; solo disponible para GERENTE.
 */
public record CrearUsuarioRequest(
        @NotBlank @Email @Size(max = 120) String email,
        @NotBlank
        @Pattern(regexp = PoliticaPassword.REGEX, message = PoliticaPassword.MENSAJE)
        String password,
        @NotBlank @SafeText @Size(max = 60) String nombre,
        @SafeText @Size(max = 60) String apellido,
        @Size(max = 20) @Pattern(regexp = "^[+0-9 ]*$", message = "solo digitos, espacios y '+'") String telefono,
        @SafeText @Size(max = 150) String direccion,
        @NotNull Rol rol) {
}
