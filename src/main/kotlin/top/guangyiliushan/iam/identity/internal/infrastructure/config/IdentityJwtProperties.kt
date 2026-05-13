package top.guangyiliushan.iam.identity.internal.infrastructure.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import java.time.Duration

@ConfigurationProperties("iam.security.jwt")
data class IdentityJwtProperties(
    val issuer: String = "https://iam.guangyiliushan.top",
    val clientId: String = "iam-basic",
    val secret: String,
    val keyId: String = "identity-hs-kid",
    val macAlgorithm: MacAlgorithm = MacAlgorithm.HS256,
    val clockSkew: Duration = Duration.ofSeconds(60),
    val replayDetectionTtlBuffer: Duration = Duration.ofSeconds(30),
    val refreshReuseDetectionWindow: Duration = Duration.ofSeconds(1),
    val accessToken: TokenSpec = TokenSpec(
        audience = "iam-api",
        ttl = Duration.ofMinutes(15),
        type = "at+jwt"
    ),
    val refreshToken: TokenSpec = TokenSpec(
        audience = "iam-refresh",
        ttl = Duration.ofDays(30),
        type = "rt+jwt"
    )
) {
    init {
        require(issuer.isNotBlank()) { "JWT issuer 不能为空" }
        require(clientId.isNotBlank()) { "JWT clientId 不能为空" }
        require(secret.isNotBlank()) { "JWT secret 不能为空" }
        require(keyId.isNotBlank()) { "JWT keyId 不能为空" }
    }

    data class TokenSpec(
        val audience: String,
        val ttl: Duration,
        val type: String
    ) {
        init {
            require(audience.isNotBlank()) { "JWT audience 不能为空" }
            require(!ttl.isNegative && !ttl.isZero) { "JWT ttl 必须大于 0" }
            require(type.isNotBlank()) { "JWT typ 不能为空" }
        }
    }
}