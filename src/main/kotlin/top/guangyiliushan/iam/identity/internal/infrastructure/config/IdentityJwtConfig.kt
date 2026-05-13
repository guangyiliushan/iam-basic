package top.guangyiliushan.iam.identity.internal.infrastructure.config

import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtAudienceValidator
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.jwt.JwtClaimValidator
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtIssuerValidator
import org.springframework.security.oauth2.jwt.JwtTimestampValidator
import org.springframework.security.oauth2.jwt.JwtTypeValidator
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import java.time.Clock
import java.time.Instant
import java.util.Base64
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@Configuration
@EnableConfigurationProperties(IdentityJwtProperties::class)
class IdentityJwtConfig {

    @Bean
    fun jwtClock(): Clock = Clock.systemUTC()

    @Bean
    fun jwtSecretKey(jwtProperties: IdentityJwtProperties): SecretKey {
        val secretBytes = decodeSecret(jwtProperties)
        require(secretBytes.size >= minKeyLength(jwtProperties.macAlgorithm)) {
            "iam.security.jwt.secret 的 Base64 解码长度不足，无法满足 ${jwtProperties.macAlgorithm.name} 的最小密钥要求"
        }
        return SecretKeySpec(secretBytes, jcaName(jwtProperties.macAlgorithm.name))
    }

    @Bean
    fun jwtEncoder(secretKey: SecretKey, jwtProperties: IdentityJwtProperties): JwtEncoder =
        NimbusJwtEncoder.withSecretKey(secretKey)
            .algorithm(jwtProperties.macAlgorithm)
            .jwkPostProcessor { it.keyID(jwtProperties.keyId) }
            .build()

    @Bean("accessTokenValidator")
    fun accessTokenValidator(jwtProperties: IdentityJwtProperties): OAuth2TokenValidator<Jwt> =
        tokenValidator(
            jwtProperties,
            jwtProperties.accessToken.audience,
            jwtProperties.accessToken.type,
            requiredStringClaim(JwtClaimNames.SUB),
            requiredStringClaim(JwtClaimNames.JTI),
            requiredInstantClaim(JwtClaimNames.IAT),
            exactValueClaim(CLAIM_CLIENT_ID, jwtProperties.clientId),
            requiredStringClaim(CLAIM_SESSION_ID),
            nonNegativeNumberClaim(CLAIM_TOKEN_VERSION),
            exactValueClaim(CLAIM_TOKEN_USE, TOKEN_USE_ACCESS)
        )

    @Bean("refreshTokenValidator")
    fun refreshTokenValidator(jwtProperties: IdentityJwtProperties): OAuth2TokenValidator<Jwt> =
        tokenValidator(
            jwtProperties,
            jwtProperties.refreshToken.audience,
            jwtProperties.refreshToken.type,
            requiredStringClaim(JwtClaimNames.SUB),
            requiredStringClaim(JwtClaimNames.JTI),
            requiredInstantClaim(JwtClaimNames.IAT),
            exactValueClaim(CLAIM_CLIENT_ID, jwtProperties.clientId),
            requiredStringClaim(CLAIM_SESSION_ID),
            requiredStringClaim(CLAIM_TOKEN_FAMILY_ID),
            nonNegativeNumberClaim(CLAIM_TOKEN_ROTATION),
            exactValueClaim(CLAIM_TOKEN_USE, TOKEN_USE_REFRESH)
        )

    @Bean("accessTokenDecoder")
    fun accessTokenDecoder(
        secretKey: SecretKey,
        jwtProperties: IdentityJwtProperties,
        @Qualifier("accessTokenValidator") validator: OAuth2TokenValidator<Jwt>
    ): JwtDecoder = jwtDecoder(secretKey, jwtProperties.macAlgorithm, validator)

    @Bean("refreshTokenDecoder")
    fun refreshTokenDecoder(
        secretKey: SecretKey,
        jwtProperties: IdentityJwtProperties,
        @Qualifier("refreshTokenValidator") validator: OAuth2TokenValidator<Jwt>
    ): JwtDecoder = jwtDecoder(secretKey, jwtProperties.macAlgorithm, validator)

    private fun decodeSecret(jwtProperties: IdentityJwtProperties): ByteArray = try {
        Base64.getDecoder().decode(jwtProperties.secret.trim())
    } catch (ex: IllegalArgumentException) {
        throw IllegalStateException("iam.security.jwt.secret 必须是合法的 Base64 字符串", ex)
    }

    private fun minKeyLength(macAlgorithm: MacAlgorithm): Int = when (macAlgorithm) {
        MacAlgorithm.HS384 -> 48
        MacAlgorithm.HS512 -> 64
        else -> 32
    }

    private fun jcaName(macAlgorithm: String): String = when (macAlgorithm) {
        "HS384" -> "HmacSHA384"
        "HS512" -> "HmacSHA512"
        else -> "HmacSHA256"
    }

    private fun tokenValidator(
        jwtProperties: IdentityJwtProperties,
        audience: String,
        type: String,
        vararg validators: OAuth2TokenValidator<Jwt>
    ): OAuth2TokenValidator<Jwt> = DelegatingOAuth2TokenValidator(
        JwtTimestampValidator(jwtProperties.clockSkew),
        JwtIssuerValidator(jwtProperties.issuer),
        JwtAudienceValidator(audience),
        JwtTypeValidator(type),
        *validators
    )

    private fun jwtDecoder(
        secretKey: SecretKey,
        macAlgorithm: MacAlgorithm,
        validator: OAuth2TokenValidator<Jwt>
    ): JwtDecoder = NimbusJwtDecoder.withSecretKey(secretKey)
        .macAlgorithm(macAlgorithm)
        .validateType(false)
        .build()
        .also { it.setJwtValidator(validator) }

    private fun requiredStringClaim(name: String): OAuth2TokenValidator<Jwt> =
        JwtClaimValidator<Any>(name) { it is String && it.isNotBlank() }

    private fun requiredInstantClaim(name: String): OAuth2TokenValidator<Jwt> =
        JwtClaimValidator<Any>(name) { it is Instant }

    private fun nonNegativeNumberClaim(name: String): OAuth2TokenValidator<Jwt> =
        JwtClaimValidator<Any>(name) { it is Number && it.toLong() >= 0 }

    private fun exactValueClaim(name: String, expectedValue: String): OAuth2TokenValidator<Jwt> =
        JwtClaimValidator<Any>(name) { it == expectedValue }

    private companion object {
        const val CLAIM_CLIENT_ID = "client_id"
        const val CLAIM_SESSION_ID = "sid"
        const val CLAIM_TOKEN_FAMILY_ID = "fid"
        const val CLAIM_TOKEN_ROTATION = "rot"
        const val CLAIM_TOKEN_USE = "token_use"
        const val CLAIM_TOKEN_VERSION = "ver"
        const val TOKEN_USE_ACCESS = "access"
        const val TOKEN_USE_REFRESH = "refresh"
    }
}