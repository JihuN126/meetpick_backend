package com.umc.meetpick.common.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {

    private final SecretKey secretKey;
    
    private static final long EXPIRATION_TIME = 1000L * 60 * 60 * 24 * 7;

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        log.info("🔹 Loaded JWT Secret length: {}", secret == null ? 0 : secret.length());
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /** JWT 생성 (memberId subject) */
    public String generateToken(Long memberId) {
        return Jwts.builder()
                .setSubject(String.valueOf(memberId))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /** 토큰에서 memberId 꺼내기 */
    public Long getMemberId(String token) {
        String sub = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        return Long.parseLong(sub);
    }

    /** 검증 + memberId 반환 */
    public Long validateToken(String token) {
        return getMemberId(token);
    }
}
