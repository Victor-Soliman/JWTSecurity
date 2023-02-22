package com.soliman.JWTSecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component  // to tell spring that this is a bean
@RequiredArgsConstructor  // in case I create a private final field , it will generate a constructor fo it
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    // this method has 3 parameters, THEY SHOULD NOT BE NULL:
    // 1. request :who will come from the DB,
    // 2. response :who will go to the client // that means that I can add new data to my response who will go out ( like adding a header)
    // 3. filterChain : a design patern (chain of responsibilities): contains a list of other filters we need to execute,
    // like saying doFilter() : it will call the next filter within the chain
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authentication");
        final String jwt;
        final String userEmail; // in the 2 step

        // here we do the check :
        // 1.
        // if the there is no token coming , or if the token doesn't start with "Bearer " : check the next filter
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return; // if this is the case don't continue
        }
        // now we need to extract the token from the authHeader
        jwt = authHeader.substring(7); // because the count of the "Bearer " is 7

        userEmail = jwtService.extractUsername(jwt); // 2. second step: we created a jwtService class that have a
        // method that accept a jwt as parameter th extract the username from the jwt (email)

        // after we get the username
        // 3. we check if the userEmail is not null , and that it is not authenticated because if it is authenticated :
        // I don't need to go through the hole process of security and let it go to the dispatcherServlet directly
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // we need to get user from the database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // we check if the token is still valid or not
            if (jwtService.isTokenValid(jwt, userDetails)) {

                // this object is needed by security to update the security context
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // when we created the user we didn't have credentials
                        userDetails.getAuthorities()
                );

                // after that we need to give it some details
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // update the security context holder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            // finally we don't forget to pass the hand to the next filter to be executed
            filterChain.doFilter(request,response);
        }

    }
}
