package com.petsalud.backendpetsalud.dto;

public record AuthResponse(String token, String tipo, long expiraEnSegundos, String email, String rol) {
}
