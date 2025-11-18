package com.pointerview.api.authorization_server.mapper;

import com.pointerview.api.authorization_server.persistence.entity.security.ClientApp;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.Date;
import java.util.stream.Collectors;

public class ClientAppMapper {

    public static RegisteredClient toRegisteredClient(ClientApp clientApp){
        // Id es muy parecido al clientId
        RegisteredClient client = RegisteredClient.withId(clientApp.getClientId())
                // id del cliente
                .clientId(clientApp.getClientId())
                // password para el cliente
                .clientSecret(clientApp.getClientSecret())
                // momento de la creacion del cliente
                .clientIdIssuedAt(new Date(System.currentTimeMillis()).toInstant())
                .clientAuthenticationMethods(clientAuthMethods -> {
                    clientApp.getClientAuthenticationMethods().stream()
                            /*Los ClientAuthenticationMethod son los metodos para enviar el clientId
                            * y el clientSecret, en este caso en vez de enviar mediante el metodo
                            * CLIENT_SECRET_JWT, se usará el metodo de envío ClientAuthenticationMethod*/
                            .map(ClientAuthenticationMethod::new)
                            .forEach(clientAuthMethods::add);
                })
                .authorizationGrantTypes(authGrantTypes -> {
                    clientApp.getAuthorizationGrantTypes().stream()
                            /*Los AuthorizationGrantType son los tipos de intercambios que hay entre el
                            * cliente y el authorization server, puede ser un authorization_code, un refresh_token
                            * o un client_credentials */
                            .map(AuthorizationGrantType::new)
                            .forEach(authGrantTypes::add);
                })
                /* representan las uris donde se redireccionaran los authorization_codes*/
                .redirectUris(redirectUris ->
                        redirectUris.addAll(clientApp.getRedirectUris()))
                .scopes(scopes ->
                        scopes.addAll(clientApp.getScopes()))
                /*Configura el token para este cliente especifico como su tiempo de expiracion*/
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(clientApp.getDurationInMinutes()))
                        .refreshTokenTimeToLive(Duration.ofMinutes(clientApp.getDurationInMinutes() * 4L))
                        .build())
                // Indica que tipo de flujo quiere seguir el cliente
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(clientApp.isRequiredProofKey())
                        .build())
                .build();

        return client;
    }
}
