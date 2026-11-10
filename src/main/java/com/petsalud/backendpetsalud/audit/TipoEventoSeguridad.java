package com.petsalud.backendpetsalud.audit;

public enum TipoEventoSeguridad {
    LOGIN_EXITOSO,
    LOGIN_FALLIDO,
    CUENTA_BLOQUEADA,
    TOKEN_INVALIDO,
    ACCESO_NO_AUTENTICADO,
    ACCESO_DENEGADO,
    ENTRADA_RECHAZADA,
    ACTIVIDAD_SOSPECHOSA
}
