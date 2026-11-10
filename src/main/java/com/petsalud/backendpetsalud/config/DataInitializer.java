package com.petsalud.backendpetsalud.config;

import com.petsalud.backendpetsalud.entity.Mascota;
import com.petsalud.backendpetsalud.entity.Producto;
import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.repository.MascotaRepository;
import com.petsalud.backendpetsalud.repository.ProductoRepository;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * Datos de demostracion SOLO para los perfiles dev y test (nunca en produccion).
 */
@Component
@Profile({"dev", "test"})
public class DataInitializer implements CommandLineRunner {

    private final UsuarioRepository usuarioRepository;
    private final MascotaRepository mascotaRepository;
    private final ProductoRepository productoRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UsuarioRepository usuarioRepository, MascotaRepository mascotaRepository,
                           ProductoRepository productoRepository, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.mascotaRepository = mascotaRepository;
        this.productoRepository = productoRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (usuarioRepository.count() > 0) {
            return;
        }
        crear("gerente@petsalud.cl", "Gerente#2025", "Gabriela", "Gerente", Rol.GERENTE);
        crear("empleado@petsalud.cl", "Empleado#2025", "Esteban", "Veterinario", Rol.EMPLEADO);
        Usuario cliente = crear("cliente@petsalud.cl", "Cliente#2025", "Camila", "Cliente", Rol.CLIENTE);
        Usuario cliente2 = crear("cliente2@petsalud.cl", "Cliente#2025", "Carlos", "Cliente", Rol.CLIENTE);
        crear("bloqueo@petsalud.cl", "Bloqueo#2025", "Benito", "Prueba", Rol.CLIENTE);

        mascotaRepository.save(Mascota.builder().nombre("Firulais").especie("Perro").raza("Mestizo")
                .fechaNacimiento(LocalDate.of(2020, 5, 10)).sexo("M").propietario(cliente).build());
        mascotaRepository.save(Mascota.builder().nombre("Luna").especie("Gato").raza("Siames")
                .fechaNacimiento(LocalDate.of(2021, 3, 2)).sexo("H").propietario(cliente2).build());

        productoRepository.save(Producto.builder().nombre("Alimento Premium Perro 15kg")
                .descripcion("Alimento balanceado adulto").precio(new BigDecimal("39990")).stock(20)
                .categoria("Alimentos").build());
        productoRepository.save(Producto.builder().nombre("Collar Antipulgas")
                .descripcion("Proteccion 8 meses").precio(new BigDecimal("15990")).stock(3)
                .categoria("Accesorios").build());
    }

    private Usuario crear(String email, String password, String nombre, String apellido, Rol rol) {
        return usuarioRepository.save(Usuario.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .nombre(nombre)
                .apellido(apellido)
                .rol(rol)
                .build());
    }
}
