package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.audit.SecurityAuditService;
import com.petsalud.backendpetsalud.audit.TipoEventoSeguridad;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro que valida el JWT (cabecera Authorization: Bearer ...) antes de procesar cada solicitud.
 * Si el token es valido, autentica al usuario en el SecurityContext; si no, deja la solicitud
 * sin autenticar y el AuthenticationEntryPoint responde 401.
 * No se registra como @Component para evitar que Spring Boot lo agregue dos veces a la cadena.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String ATRIBUTO_ERROR_JWT = "petsalud.jwt.error";
    private static final String PREFIJO = "Bearer ";

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final SecurityAuditService auditoria;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService,
                                   SecurityAuditService auditoria) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.auditoria = auditoria;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String cabecera = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (cabecera == null || !cabecera.startsWith(PREFIJO)) {
            chain.doFilter(request, response);
            return;
        }
        String token = cabecera.substring(PREFIJO.length()).trim();
        try {
            Claims claims = jwtUtil.validarToken(token);
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                // Se recarga el usuario desde BD: si fue eliminado o cambio su rol, el cambio aplica de inmediato.
                UserDetails usuario = userDetailsService.loadUserByUsername(claims.getSubject());
                UsernamePasswordAuthenticationToken autenticacion =
                        new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
                autenticacion.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(autenticacion);
            }
        } catch (JwtException | IllegalArgumentException | UsernameNotFoundException e) {
            SecurityContextHolder.clearContext();
            request.setAttribute(ATRIBUTO_ERROR_JWT, Boolean.TRUE);
            auditoria.registrar(TipoEventoSeguridad.TOKEN_INVALIDO, null, request.getRemoteAddr(),
                    request.getRequestURI(), e.getClass().getSimpleName());
        }
        chain.doFilter(request, response);
    }
}
