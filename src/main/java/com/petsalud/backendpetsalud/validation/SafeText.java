package com.petsalud.backendpetsalud.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Rechaza texto con marcado HTML/JS potencialmente peligroso (defensa contra XSS almacenado).
 */
@Documented
@Constraint(validatedBy = SafeTextValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface SafeText {
    String message() default "contiene caracteres o patrones no permitidos (posible XSS)";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
