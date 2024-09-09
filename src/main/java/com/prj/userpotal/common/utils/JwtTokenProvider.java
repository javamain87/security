package com.prj.userpotal.common.utils;

import com.prj.userpotal.common.service.UserSecurityService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value(("${jwt.validityInMilliseconds}"))
    private Long validityInMilliseconds;
    @Value("${jwt.secretKey}")
    private String secretKey;
    private final UserSecurityService userSecurityService;

    public String createToken(String username, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);
        Key key = getKeyBase64EncodingKey(encodeBase64SecreKey(secretKey));
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userSecurityService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUsername(String token) {
        Key key = getKeyBase64EncodingKey(encodeBase64SecreKey(secretKey));
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJwt(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token) {
        Key key = getKeyBase64EncodingKey(encodeBase64SecreKey(secretKey));
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJwt(token);
            return true;
        } catch (MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            // Log the exception
            return false;
        }
    }
    public String encodeBase64SecreKey(String secreKey) {
        return Encoders.BASE64.encode(secreKey.getBytes());
    }

    private Key getKeyBase64EncodingKey(String base64secreKey){
        byte[] keyBytes = Decoders.BASE64.decode(base64secreKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
