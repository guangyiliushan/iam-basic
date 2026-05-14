package top.guangyiliushan.iam.shared.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.context.NullSecurityContextRepository
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfig {
    @Bean
    @Order(2)  // ← 优先级低于其他模块化单体
    fun defaultFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .securityMatcher("/**")  // ← 匹配所有剩余路径
            .csrf { it.disable() } // ← 关闭 CSRF 保护
            .cors { } // ← 启用 CORS，使用下面定义的 CorsConfigurationSource
            .sessionManagement {
                it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // ← 禁用会话管理，适用于 REST API
            }
            .securityContext {
                it.securityContextRepository(NullSecurityContextRepository()) // ← 禁用 SecurityContext 存储，完全无状态
            }
            .requestCache { it.disable() } // ← 禁用请求缓存，因为 Spring Security 默认启用了缓存
            .formLogin { it.disable() } // ← 禁用表单登录
            .httpBasic { it.disable() } // ← 禁用 HTTP Basic 认证
            .logout { it.disable() }    // ← 禁用注销功能
            .authorizeHttpRequests { auth ->
                auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // ← 允许 OPTIONS 请求
                auth.requestMatchers(
                    "/actuator/health",
                    "/swagger-ui/**",
                    "/v3/api-docs/**",
                    "/error"
                ).permitAll()
                auth.anyRequest().denyAll()  // ← 默认拒绝（更安全）
            }
            .headers { headers ->
                headers.frameOptions { it.sameOrigin() } // ← 允许 iframe 嵌套同源页面
                headers.contentTypeOptions { }  //← 禁止浏览器 MIME 类型嗅探，增强安全性
                headers.cacheControl { }    //← 禁止浏览器缓存敏感数据，防止信息泄露
            }

        return http.build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        // 使用 Argon2id
        return Argon2PasswordEncoder(
            16,      // saltLength: 盐的长度 16 字节 (128 位)，自动生成，无需手动干预
            32,     // hashLength: 最终哈希的长度 32 字节 (256 位)
            2,       // parallelism: 并行度，例如 2 核 CPU 可设为 2
            1 shl 16, // memory: 内存开销 (KiB)，即 64 MiB
            3        // iterations: 迭代次数，即 time_cost
        )
//        // 使用 BCrypt
//        return BCryptPasswordEncoder()

    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOriginPatterns = listOf("http://localhost:*")  // ← 允许的源（通配符端口）
        configuration.allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "OPTIONS")  // ← 允许的 HTTP 方法
        configuration.allowedHeaders = listOf(
            "Authorization",
            "Content-Type",
            "Accept",
            "Origin",
            "X-Requested-With"
        )  // ← 显式允许常用请求头
        configuration.exposedHeaders = listOf("Authorization")             // ← 暴露认证相关响应头
        configuration.allowCredentials = true                               // ← 允许携带凭证（Cookie）
        configuration.maxAge = 3600L                                        // ← 预检请求缓存 1 小时

        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)  // ← 应用到所有路径
        return source
    }
}
