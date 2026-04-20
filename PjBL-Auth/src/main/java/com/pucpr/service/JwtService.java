package com.pucpr.service;

import com.pucpr.model.Usuario;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtService {

    private final SecretKey signingKey;

    public JwtService() {
        String secret = System.getenv("JWT_SECRET");
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException(
                    "Variável de ambiente JWT_SECRET não definida ou menor que 32 caracteres."
            );
        }
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateToken(Usuario user) {
        return Jwts.builder()
                .subject(user.getEmail())
                .claim("role", user.getRole())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900_000)) // 15 min
                .signWith(signingKey)
                .compact();
    }

    public String extractEmail(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            System.err.println("Token expirado: " + e.getMessage());
            return false;
        } catch (JwtException e) {
            System.err.println("Token inválido: " + e.getMessage());
            return false;
        }
    }
}
