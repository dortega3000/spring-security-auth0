package com.ornaapplabs.spring.security.auth0;

/**
 * Created by dortega on 9/7/14.
 */

import org.springframework.context.annotation.Import;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

@Retention(value=java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value={java.lang.annotation.ElementType.TYPE})
@Import({Auth0SecurityConfiguration.class})
public @interface EnableAuth0Security {

}