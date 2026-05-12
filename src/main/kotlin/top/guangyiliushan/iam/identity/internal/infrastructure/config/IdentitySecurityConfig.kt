package top.guangyiliushan.iam.identity.internal.infrastructure.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.context.NullSecurityContextRepository

@Configuration
class IdentitySecurityConfig {

    @Bean
    @Order(1)
    fun identityFilterChain(http: HttpSecurity): SecurityFilterChain {
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
            .authorizeHttpRequests { auth ->
                auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                auth.requestMatchers(
                    HttpMethod.POST,
                    "/api/iam/login",
                    "/api/iam/register"
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
