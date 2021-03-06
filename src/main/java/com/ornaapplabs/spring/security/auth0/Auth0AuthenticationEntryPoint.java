package com.ornaapplabs.spring.security.auth0;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Component
public class Auth0AuthenticationEntryPoint implements AuthenticationEntryPoint {
    @SuppressWarnings("deprecation")
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        PrintWriter writer = response.getWriter();


        if (authException instanceof Auth0TokenException) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
            writer.println("HTTP Status " + HttpServletResponse.SC_UNAUTHORIZED + " - " + authException.getMessage());
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN, authException.getMessage());
            writer.println("HTTP Status " + HttpServletResponse.SC_FORBIDDEN + " - " + authException.getMessage());
        }
    }

}