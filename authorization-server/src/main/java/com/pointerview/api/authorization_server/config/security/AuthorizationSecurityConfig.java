package com.pointerview.api.authorization_server.config.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@EnableWebSecurity
@Component
public class AuthorizationSecurityConfig {

    @Bean
    @Order(1)// Indica el orden en la cadena de filtros
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer auth2AuthorizationServerConfiguration =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()); // Aplica OpenID para la autenticación con OpenIdConnect

        http.exceptionHandling(exceptionConfig -> {
            exceptionConfig.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
        });

        /*Al darle config por defecto indica que debera de aplciar las configuraciones de un Bean
        * de tipo de retorno JWKSource*/
        http.oauth2ResourceServer(oauthResourceServerConfig -> {
            oauthResourceServerConfig.jwt(Customizer.withDefaults());
        });

        return http.build();
    }


    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authConfig -> {
            authConfig
                    .requestMatchers("/login").permitAll()
                    .anyRequest().authenticated();
        }).formLogin(Customizer.withDefaults());

        return http.build();
    }

    /*
     * JWT -> Estandar abstracto por lo que debe de ser implementado
     *   JWS(Signed) -> El mas comun y mas usado tomando el Header + Body + Firma(Header+Body) + HS256
     *   JWE(Encripted) -> Muy parecido al JWS pero no usa HS256 sino RS256 basado en llaves RSA publicas y privadas
     *                   y para este tipo de tokens se usan los JWK
     * */

    /*
    * Metodo para crear el JWE-JWK
    * */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9595")
                .build();
    }

    /*
    * Metodo para generar la key RSA usada luego para obtener la public and private key para
    * construir la RSA key y usarla para crear el JWKSet usado para retornar el JWKSoruce mediante
    * su implementacion de ImmutableJWKSet<>.
    *
    * Copiado de la documentacion al ser a parte de spring ya que es del proyecto nimbusds.jose
    * */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
