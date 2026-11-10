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
@Table(name = "expedientes_medicos")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExpedienteMedico {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private LocalDateTime fecha;

    @NotBlank
    @SafeText
    @Size(max = 1000)
    @Column(length = 1000)
    private String descripcion;

    @SafeText
    @Size(max = 500)
    @Column(length = 500)
    private String diagnostico;

    @SafeText
    @Size(max = 500)
    @Column(length = 500)
    private String tratamiento;

    // Relaciones
    @ManyToOne
    @JoinColumn(name = "mascota_id")
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private Mascota mascota;

    @ManyToOne
    @JoinColumn(name = "veterinario_id")
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    @JsonIgnoreProperties({"telefono", "direccion", "hibernateLazyInitializer", "handler"})
    private Usuario veterinario;
}
