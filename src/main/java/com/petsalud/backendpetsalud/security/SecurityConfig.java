package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.audit.SecurityAuditService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Arquitectura de seguridad:
 *  1. CORS restringido a origenes conocidos.
 *  2. API stateless: sin sesion HTTP ni cookies -> JWT en cabecera Authorization.
 *  3. CSRF deshabilitado de forma justificada: el navegador no adjunta automaticamente
 *     la cabecera Authorization, por lo que una peticion cruzada no puede autenticarse.
 *  4. Cabeceras de seguridad (CSP, X-Frame-Options, nosniff, HSTS, Referrer-Policy).
 *  5. Reglas por URL (defensa gruesa) + @PreAuthorize por metodo (defensa fina, roles y propiedad).
 *  6. Respuestas 401/403 en JSON y auditadas.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final UsuarioDetailsService usuarioDetailsService;
    private final JwtUtil jwtUtil;
    private final SecurityAuditService auditoria;
    private final RestAuthenticationEntryPoint entryPoint;
    private final RestAccessDeniedHandler accessDeniedHandler;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.cors.allowed-origins:http://localhost:4200}")
    private String origenesPermitidos;

    public SecurityConfig(UsuarioDetailsService usuarioDetailsService, JwtUtil jwtUtil,
                          SecurityAuditService auditoria, RestAuthenticationEntryPoint entryPoint,
                          RestAccessDeniedHandler accessDeniedHandler, PasswordEncoder passwordEncoder) {
        this.usuarioDetailsService = usuarioDetailsService;
        this.jwtUtil = jwtUtil;
        this.auditoria = auditoria;
        this.entryPoint = entryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(withDefaults())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .headers(h -> h
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
                        .frameOptions(f -> f.deny())
                        .contentTypeOptions(withDefaults())
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                        .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .authorizeHttpRequests(auth -> auth
                        // Publico
                        .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/registro").permitAll()
                        .requestMatchers("/error").permitAll()
                        // Solo gerencia
                        .requestMatchers("/api/auditoria/**").hasRole("GERENTE")
                        .requestMatchers(HttpMethod.GET, "/api/ventas").hasRole("GERENTE")
                        .requestMatchers(HttpMethod.DELETE, "/api/productos/**").hasRole("GERENTE")
                        // Personal (empleados y gerentes)
                        .requestMatchers(HttpMethod.POST, "/api/productos/**").hasAnyRole("EMPLEADO", "GERENTE")
                        .requestMatchers(HttpMethod.PUT, "/api/productos/**").hasAnyRole("EMPLEADO", "GERENTE")
                        .requestMatchers(HttpMethod.GET, "/api/productos/stock-bajo").hasAnyRole("EMPLEADO", "GERENTE")
                        .requestMatchers(HttpMethod.POST, "/api/expedientes/**").hasAnyRole("EMPLEADO", "GERENTE")
                        // Todo lo demas requiere autenticacion; el detalle por rol/propiedad esta en @PreAuthorize
                        .anyRequest().authenticated())
                .authenticationProvider(daoAuthenticationProvider())
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil, usuarioDetailsService, auditoria),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(usuarioDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(daoAuthenticationProvider());
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        List<String> origenes = Arrays.stream(origenesPermitidos.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).toList();
        config.setAllowedOrigins(origenes);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(false);
        config.setMaxAge(Duration.ofHours(1));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
