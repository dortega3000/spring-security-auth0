package com.ornaapplabs.spring.security.auth0;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Created by dortega on 9/7/14.
 */
@Configuration
public class Auth0SecurityConfiguration {

    @Value("${auth0.clientSecret:}")
    private String clientSecret;
    @Value("${auth0.clientId:}")
    private String clientId;
    @Value("${auth0.validatePreFlight:true}")
    private boolean validatePreFlight;

    @Bean
    public AuthenticationEntryPoint Auth0AuthenticationEntryPoint() {
        return new Auth0AuthenticationEntryPoint();
    }

    @Bean
    public GenericFilterBean Auth0AuthenticationFilter() {
        GenericFilterBean filter = new Auth0AuthenticationFilter(Auth0AuthenticationProvider(), Auth0AuthenticationEntryPoint(), validatePreFlight);
        return filter;
    }

    @Bean
    public AuthenticationProvider Auth0AuthenticationProvider() {
        return new Auth0AuthenticationProvider(clientSecret, clientId);
    }
}
