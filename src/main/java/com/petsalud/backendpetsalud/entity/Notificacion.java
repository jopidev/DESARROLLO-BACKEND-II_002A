package com.petsalud.backendpetsalud.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.petsalud.backendpetsalud.validation.SafeText;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "notificaciones")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Notificacion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @SafeText
    @Size(max = 500)
    @Column(length = 500)
    private String mensaje;

    @SafeText
    @Size(max = 30)
    private String tipo; // "Promocion", "Recordatorio", "Evento"

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private LocalDateTime fecha;

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private Boolean leida;

    // Relaciones
    @ManyToOne
    @JoinColumn(name = "usuario_id")
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    @JsonIgnoreProperties({"telefono", "direccion", "rol", "hibernateLazyInitializer", "handler"})
    private Usuario usuario;
}
