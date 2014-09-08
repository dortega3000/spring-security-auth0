package com.ornaapplabs.spring.security.auth0;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter responsible to intercept the JWT in the HTTP header and attempt an authentication. It delegates the authentication to the authentication manager
 *
 * @author Daniel Teixeira
 */
@Component
public class Auth0AuthenticationFilter extends GenericFilterBean {

    private AuthenticationProvider authenticationProvider;
    private AuthenticationEntryPoint entryPoint;
    private Boolean validatePreFlight = true;

    private static final String STR_SCHEME = "Bearer";
    private static final String STR_ACCESS_CONTROL_REQUEST_METHOD = "Access-Control-Request-Method";
    private static final String STR_OPTIONS = "OPTIONS";
    private static final String STR_AUTHORIZATION_HEADER = "authorization";

    public Auth0AuthenticationFilter(AuthenticationProvider authenticationProvider, AuthenticationEntryPoint entryPoint, Boolean validatePreFlight) {
        this.authenticationProvider = authenticationProvider;
        this.entryPoint = entryPoint;
        this.validatePreFlight = validatePreFlight;
    }


    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        String jwt = getToken((HttpServletRequest) request);

        if ((jwt != null) && ((validatePreFlight) ||
                (!((request.getHeader(STR_ACCESS_CONTROL_REQUEST_METHOD) != null) && (request.getMethod().equals(STR_OPTIONS)))))) {
            try {
                Auth0JWTToken token = new Auth0JWTToken(jwt);
                Authentication authResult = authenticationProvider.authenticate(token);
                SecurityContextHolder.getContext().setAuthentication(authResult);

            } catch (AuthenticationException failed) {
                SecurityContextHolder.clearContext();
                entryPoint.commence(request, response, failed);
                return;
            }
        }

        chain.doFilter(request, response);

    }

    /**
     * Looks at the authorization bearer and extracts the JWT
     */
    private String getToken(HttpServletRequest httpRequest) {
        String token = null;
        final String authorizationHeader = httpRequest.getHeader(STR_AUTHORIZATION_HEADER);
        if (authorizationHeader == null) {
            return null;
        }

        String[] parts = authorizationHeader.split(" ");
        if (parts.length != 2) {
            return null;
        }

        String scheme = parts[0];
        String credentials = parts[1];

        if (scheme.equals(STR_SCHEME)) {
            token = credentials;
        }
        return token;
    }

    public AuthenticationEntryPoint getEntryPoint() {
        return entryPoint;
    }

    public Boolean getValidatePreFlight() {
        return validatePreFlight;
    }

    public void setValidatePreFlight(Boolean validatePreFlight) {
        this.validatePreFlight = validatePreFlight;
    }
}