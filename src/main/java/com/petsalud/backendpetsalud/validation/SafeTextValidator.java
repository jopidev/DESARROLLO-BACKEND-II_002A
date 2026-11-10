package com.petsalud.backendpetsalud.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class SafeTextValidator implements ConstraintValidator<SafeText, String> {

    private static final Pattern PELIGROSO = Pattern.compile(
            "(?i)(<|>|javascript:|vbscript:|data:text/html|\\bon[a-z]+\\s*=|&#|%3c|%3e)");

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value == null || !PELIGROSO.matcher(value).find();
    }
}
