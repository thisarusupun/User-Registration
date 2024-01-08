package com.example.jwt.security.jwt;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    // for signature of the token
    @Value("${jwtSecret}")
    private String jwtSecret;

    // for expire time of token
    @Value("${jwtExpiration}")
    private int jwtExpirationMs; //in miliseconds

    // Create Token
    public String generateJwtToken(Authentication authentication){

        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();

        return Jwts.builder()
            .setSubject(userPrincipal.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date((new Date()).getTime()+jwtExpirationMs))
            .signWith(key(), SignatureAlgorithm.HS256)
            .compact();
    }

    // Create key to encrypt the token
    public Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    // Validate Token
    public boolean validateJwtToken(String authToken){
        try{
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e){ // token changed in client side unauthorized way
            logger.error("Invalid JWT Token: {}",e.getMessage());
        } catch (ExpiredJwtException e){
            logger.error("JWT Token Is Expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e){
            logger.error("Unsupported JWT: {}", e.getMessage());
        } catch (IllegalArgumentException e){
            logger.error("JWT PayLoad Is Empty: {}", e.getMessage());
        }
        return false;
    }

    // Username from subject
    public String getUsernameFromJwtToken(String authToken){
        return Jwts
        .parserBuilder()
        .setSigningKey(key())
        .build()
        .parseClaimsJws(authToken)
        .getBody()
        .getSubject();
    }
}
