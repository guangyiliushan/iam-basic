package top.guangyiliushan.iam.identity.internal.infrastructure.config

import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.context.NullSecurityContextRepository
import top.guangyiliushan.iam.identity.internal.infrastructure.security.jwt.JwtAuthenticationConverter

@Configuration
class IdentitySecurityConfig {

    @Bean
    @Order(0)
    fun publicEndpointsFilterChain(
        http: HttpSecurity
    ): SecurityFilterChain {
        http
            .securityMatcher("/oauth2/**", "/.well-known/**")
            .csrf { it.disable() }
            .cors { }
            .sessionManagement {
                it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            }
            .securityContext {
                it.securityContextRepository(NullSecurityContextRepository())
            }
            .requestCache { it.disable() }
            .formLogin { it.disable() }
            .httpBasic { it.disable() }
            .logout { it.disable() }
            .authorizeHttpRequests { auth ->
                auth.anyRequest().permitAll()
            }
            .headers { headers ->
                headers.frameOptions { it.sameOrigin() }
                headers.contentTypeOptions { }
                headers.cacheControl { }
            }

        return http.build()
    }

    @Bean
    @Order(1)
    fun identityFilterChain(
        http: HttpSecurity,
        @Qualifier("accessTokenDecoder") accessTokenDecoder: JwtDecoder,
        jwtAuthenticationConverter: JwtAuthenticationConverter
    ): SecurityFilterChain {
        http
            .securityMatcher("/api/iam/**")
            .csrf { it.disable() }
            .cors { }
            .sessionManagement {
                it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            }
            .securityContext {
                it.securityContextRepository(NullSecurityContextRepository())
            }
            .requestCache { it.disable() }
            .formLogin { it.disable() }
            .httpBasic { it.disable() }
            .logout { it.disable() }
            .oauth2ResourceServer { oauth2 ->
                oauth2.jwt { jwt ->
                    jwt.decoder(accessTokenDecoder)
                    jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)
                }
            }
            .authorizeHttpRequests { auth ->
                auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                auth.requestMatchers(
                    HttpMethod.POST,
                    "/api/iam/login",
                    "/api/iam/register",
                    "/api/iam/logout",
                    "/api/iam/refresh"
                ).permitAll()
                auth.anyRequest().authenticated()
            }
            .headers { headers ->
                headers.frameOptions { it.sameOrigin() }
                headers.contentTypeOptions { }
                headers.cacheControl { }
            }

        return http.build()
    }
}
