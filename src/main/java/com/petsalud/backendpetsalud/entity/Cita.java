package com.petsalud.backendpetsalud.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.petsalud.backendpetsalud.validation.SafeText;
import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "citas")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Cita {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDateTime fechaHora;

    @Size(max = 20)
    private String estado; // "Agendada", "Confirmada", "Cancelada", "Completada"

    @SafeText
    @Size(max = 255)
    private String motivo;

    // Relaciones
    @ManyToOne
    @JoinColumn(name = "mascota_id")
    private Mascota mascota;

    @ManyToOne
    @JoinColumn(name = "veterinario_id")
    @JsonIgnoreProperties({"telefono", "direccion", "hibernateLazyInitializer", "handler"})
    private Usuario veterinario;
}
