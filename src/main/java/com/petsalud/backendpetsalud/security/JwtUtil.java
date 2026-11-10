package com.petsalud.backendpetsalud.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Generacion y validacion de JWT firmados con HMAC-SHA256.
 * - La clave se lee de la propiedad jwt.secret (variable de entorno JWT_SECRET en produccion), en Base64, >= 256 bits.
 * - El token incluye: jti, iss, sub (email), roles, iat y exp (vida corta, 15 min por defecto).
 * - La validacion exige firma valida, algoritmo HMAC (se rechazan tokens sin firma "alg:none"),
 *   emisor correcto y token no expirado.
 */
@Component
public class JwtUtil {

    private final SecretKey clave;
    private final long expiracionMs;
    private final String emisor;

    public JwtUtil(@Value("${jwt.secret}") String secretoBase64,
                   @Value("${jwt.expiration-ms:900000}") long expiracionMs,
                   @Value("${jwt.issuer:petsalud-backend}") String emisor) {
        byte[] bytes = Decoders.BASE64.decode(secretoBase64);
        if (bytes.length < 32) {
            throw new IllegalStateException("jwt.secret debe tener al menos 256 bits (32 bytes en Base64)");
        }
        this.clave = Keys.hmacShaKeyFor(bytes);
        this.expiracionMs = expiracionMs;
        this.emisor = emisor;
    }

    public String generarToken(UserDetails usuario) {
        return generarToken(usuario, expiracionMs);
    }

    public String generarToken(UserDetails usuario, long validezMs) {
        Date ahora = new Date();
        List<String> roles = usuario.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(emisor)
                .subject(usuario.getUsername())
                .claim("roles", roles)
                .issuedAt(ahora)
                .expiration(new Date(ahora.getTime() + validezMs))
                .signWith(clave, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * @return claims del token si es valido
     * @throws JwtException si la firma, el emisor o la expiracion no son validos
     */
    public Claims validarToken(String token) {
        return Jwts.parser()
                .verifyWith(clave)
                .requireIssuer(emisor)
                .clockSkewSeconds(30)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extraerEmail(String token) {
        return validarToken(token).getSubject();
    }

    public long getExpiracionMs() {
        return expiracionMs;
    }
}
