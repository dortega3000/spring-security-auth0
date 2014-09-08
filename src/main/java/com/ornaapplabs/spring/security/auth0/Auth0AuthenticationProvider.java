package com.ornaapplabs.spring.security.auth0;

import com.auth0.jwt.JWTVerifier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Map;

/**
 * Class that verifies the JWT token and in case of beeing valid, it will set the userdetails in the authentication object
 *
 * @author Daniel Teixeira
 */

@Component
public class Auth0AuthenticationProvider implements AuthenticationProvider {

    private JWTVerifier jwtVerifier = null;
    private String clientSecret = null;
    private String clientId = null;


    private final Log logger = LogFactory.getLog(getClass());

    public Auth0AuthenticationProvider(String clientSecret, String clientId) {
        this.clientSecret = clientSecret;
        this.clientId = clientId;

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        createVerifier();
        String token = ((Auth0JWTToken) authentication).getJwt();

        logger.info("Trying to authenticate with token: " + token);


        Map<String, Object> decoded;
        try {

            decoded = jwtVerifier.verify(token);
            logger.debug("Decoded JWT token" + decoded);
            ((Auth0JWTToken) authentication).setAuthenticated(true);
            ((Auth0JWTToken) authentication).setPrincipal(new Auth0UserDetails(decoded));
            ((Auth0JWTToken) authentication).setDetails(decoded);
            return authentication;

        } catch (InvalidKeyException e) {
            logger.debug("InvalidKeyException thrown while decoding JWT token " + e.getLocalizedMessage());
            throw new Auth0TokenException(e);
        } catch (NoSuchAlgorithmException e) {
            logger.debug("NoSuchAlgorithmException thrown while decoding JWT token " + e.getLocalizedMessage());
            throw new Auth0TokenException(e);
        } catch (IllegalStateException e) {
            logger.debug("IllegalStateException thrown while decoding JWT token " + e.getLocalizedMessage());
            throw new Auth0TokenException(e);
        } catch (SignatureException e) {
            logger.debug("SignatureException thrown while decoding JWT token " + e.getLocalizedMessage());
            throw new Auth0TokenException(e);
        } catch (IOException e) {
            logger.debug("IOException thrown while decoding JWT token " + e.getLocalizedMessage());
            throw new Auth0TokenException(e);
        }
    }

    private void createVerifier() {
        if (jwtVerifier == null) {
            if ((StringUtils.isEmpty(clientId)) || (StringUtils.isEmpty(clientId))) {
                logger.warn("CliendId and/or ClientSecret are null or empty, token decryption will fail!!!!");
            }
            jwtVerifier = new JWTVerifier(clientSecret, clientId);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return Auth0JWTToken.class.isAssignableFrom(authentication);
    }


}
