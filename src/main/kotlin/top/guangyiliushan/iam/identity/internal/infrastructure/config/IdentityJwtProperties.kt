package top.guangyiliushan.iam.identity.internal.infrastructure.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.web.server.Cookie
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import java.time.Duration

@ConfigurationProperties("iam.security.jwt")
data class IdentityJwtProperties(
    val issuer: String = "https://iam.guangyiliushan.top",
    val clientId: String = "iam-basic",
    val signing: SigningSpec = SigningSpec(),
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
    ),
    val session: SessionSpec = SessionSpec(),
    val refreshTokenCookie: CookieSpec = CookieSpec(
        name = "IAM_REFRESH_TOKEN",
        path = "/api/iam/refresh"
    )
) {
    init {
        require(issuer.isNotBlank()) { "JWT issuer 不能为空" }
        require(clientId.isNotBlank()) { "JWT clientId 不能为空" }
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

    data class CookieSpec(
        val name: String,
        val path: String,
        val domain: String? = null,
        val httpOnly: Boolean = true,
        val secure: Boolean = true,
        val sameSite: Cookie.SameSite = Cookie.SameSite.STRICT,
        val maxAge: Duration? = null
    ) {
        init {
            require(name.isNotBlank()) { "JWT cookie name 不能为空" }
            require(path.startsWith("/")) { "JWT cookie path 必须以 / 开头" }
            require(maxAge == null || (!maxAge.isNegative && !maxAge.isZero)) { "JWT cookie maxAge 必须大于 0" }
        }

        fun effectiveMaxAge(defaultTtl: Duration): Duration = maxAge ?: defaultTtl

        fun sameSiteAttribute(): String? = when (sameSite) {
            Cookie.SameSite.NONE -> "None"
            Cookie.SameSite.LAX -> "Lax"
            Cookie.SameSite.STRICT -> "Strict"
            Cookie.SameSite.OMITTED -> null
        }
    }

    data class SessionSpec(
        val maxConcurrentSessions: Int = 5
    ) {
        init {
            require(maxConcurrentSessions > 0) { "JWT 最大并发会话数必须大于 0" }
        }
    }

    data class SigningSpec(
        val activeKeyId: String = "identity-hs-kid",
        val keys: List<KeySpec> = emptyList()
    ) {
        init {
            require(activeKeyId.isNotBlank()) { "JWT activeKeyId 不能为空" }
            require(keys.isNotEmpty()) { "JWT 至少需要配置一个 signing key" }
            require(keys.map(KeySpec::id).distinct().size == keys.size) { "JWT signing keys 的 id 不能重复" }
            keys.firstOrNull { it.id == activeKeyId }
                ?: throw IllegalArgumentException("JWT activeKeyId 必须命中已配置的 signing key")
        }

        fun activeKey(): KeySpec = keys.first { it.id == activeKeyId }

        fun supportedAlgorithms(): Set<JwsAlgorithm> = keys.map(KeySpec::jwsAlgorithm).toSet()
    }

    data class KeySpec(
        val id: String,
        val type: KeyType = KeyType.HS,
        val macAlgorithm: MacAlgorithm? = null,
        val signatureAlgorithm: SignatureAlgorithm? = null,
        val secret: String? = null,
        val publicKey: String? = null,
        val privateKey: String? = null
    ) {
        init {
            require(id.isNotBlank()) { "JWT key id 不能为空" }
            when (type) {
                KeyType.HS -> {
                    require(!secret.isNullOrBlank()) { "HS key 必须配置 secret" }
                    require(macAlgorithm != null) { "HS key 必须配置 macAlgorithm" }
                }

                KeyType.RSA, KeyType.EC -> {
                    require(signatureAlgorithm != null) { "${type.name} key 必须配置 signatureAlgorithm" }
                    require(!publicKey.isNullOrBlank()) { "${type.name} key 必须配置 publicKey" }
                    require(!privateKey.isNullOrBlank()) { "${type.name} key 必须配置 privateKey" }
                }
            }
        }

        fun jwsAlgorithm(): JwsAlgorithm = when (type) {
            KeyType.HS -> requireNotNull(macAlgorithm)
            KeyType.RSA, KeyType.EC -> requireNotNull(signatureAlgorithm)
        }

        fun algorithmName(): String = when (type) {
            KeyType.HS -> requireMacAlgorithm().name
            KeyType.RSA, KeyType.EC -> requireSignatureAlgorithm().name
        }

        fun requireMacAlgorithm(): MacAlgorithm = requireNotNull(macAlgorithm) { "当前 signing key 未配置 macAlgorithm" }

        fun requireSignatureAlgorithm(): SignatureAlgorithm =
            requireNotNull(signatureAlgorithm) { "当前 signing key 未配置 signatureAlgorithm" }
    }

    enum class KeyType {
        HS,
        RSA,
        EC
    }
}
