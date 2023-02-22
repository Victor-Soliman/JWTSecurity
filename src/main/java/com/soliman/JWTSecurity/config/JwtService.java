package com.soliman.JWTSecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    //2. generate a secretKey with online source like : allkeysgenerator.com with
    // minimum 256 bit (lowest recomanded for JWT)
    private static final String SECRET_KEY = "7234753778214125432A462D4A614E645267556B58703273357638792F423F45";

    public String extractUsername(String token) {
        // 5. we use the token and the claims to get the subject(username/email)
        return extractClaim(token, Claims::getSubject);
    }

    // 4.
    // extract a single claim from the token
    // like this
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // 6. we generate a method that will generate the token without extra claims ( only from userDetalis)
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }


    // 5. we generate the method that it will generate the token for us . it takes 2 parameters :
    //      1. a map of string and object that will contain the extra claims that we want to add(if I want to pass any information)
    //      2. UserDetails from spring
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        // we create the token from Jwts
        return Jwts
                .builder()
                .setClaims(extraClaims) // pass the claims
                .setSubject(userDetails.getUsername())  // the subject should be the username or email, we take it from
                .setIssuedAt(new Date(System.currentTimeMillis()))   // when this claim was created ( this will help us to know if the token is still valid or no
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // how long the token should be valid
                .signWith(getSignInkey(), SignatureAlgorithm.HS256) // which key we want to use to sign this token ( the method that we created before), also wee pass the signature algorithm
                .compact();   // the method that will generate and return the token
    }

    // 7. we will implement a method that can validate a token with 2 parameters:
    //      1. the token , and 2. the UserDetalis : to validate is this token belongs to the userDetalis
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        // the username we have within the token is the same like the one we have as input && my token is not expired
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // 8.// we create a method called extractExperation from the token we have inside thismethod
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // 9.// we use the token and Claims for each expiration
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    // before extracting the username:
    // 1.
    // we need to extract all the claims ,(we add some dependencies)
    // Claims and Jwts are from io.jsonwebtoken dependency
    private Claims extractAllClaims(String token) {
        return
                Jwts
                        // we need to parse the token
                        .parserBuilder()
                        // we need the signInKey, because when we need to generate a token we need a signInKey
                        .setSigningKey(getSignInkey()) // the implementation of this method is a bit down
                        .build() // once the object is built ,we need to parse the ClaimsJws ,and get the body
                        .parseClaimsJws(token)
                        .getBody();
    }


    // 3.
    private Key getSignInkey() {
        // we make a variable of type byte[] , we use Decoders class because we need the secret key
        // to be decoded in Base 64
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        // we use the Keys class to reach the algorithm who will generate the key for us
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
