package com.petsalud.backendpetsalud.dto;

public final class PoliticaPassword {
    /** Minimo 8 caracteres, con mayuscula, minuscula, digito y simbolo. */
    public static final String REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,100}$";
    public static final String MENSAJE =
            "debe tener entre 8 y 100 caracteres e incluir mayuscula, minuscula, numero y simbolo";

    private PoliticaPassword() {
    }
}
