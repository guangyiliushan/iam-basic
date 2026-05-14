package top.guangyiliushan.iam.identity.internal.infrastructure.config

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
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
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Clock
import java.time.Instant
import java.util.Base64
import top.guangyiliushan.iam.identity.internal.infrastructure.security.jwt.CommonJwtClaims

@Configuration
@EnableConfigurationProperties(IdentityJwtProperties::class)
class IdentityJwtConfig {

    @Bean
    fun jwtClock(): Clock = Clock.systemUTC()

    @Bean
    fun jwtJwkSource(jwtProperties: IdentityJwtProperties): JWKSource<SecurityContext> =
        ImmutableJWKSet(JWKSet(jwtProperties.signing.keys.map(::toJwk)))

    @Bean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext>): JwtEncoder = NimbusJwtEncoder(jwkSource)

    @Bean("accessTokenValidator")
    fun accessTokenValidator(jwtProperties: IdentityJwtProperties): OAuth2TokenValidator<Jwt> =
        tokenValidator(
            jwtProperties,
            jwtProperties.accessToken.audience,
            jwtProperties.accessToken.type,
            requiredStringClaim(JwtClaimNames.SUB),
            requiredStringClaim(JwtClaimNames.JTI),
            requiredInstantClaim(JwtClaimNames.IAT),
            exactValueClaim(CommonJwtClaims.CLAIM_CLIENT_ID, jwtProperties.clientId),
            requiredStringClaim(CommonJwtClaims.CLAIM_SESSION_ID),
            nonNegativeNumberClaim(CommonJwtClaims.CLAIM_TOKEN_VERSION),
            exactValueClaim(CommonJwtClaims.CLAIM_TOKEN_USE, CommonJwtClaims.TOKEN_USE_ACCESS)
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
            exactValueClaim(CommonJwtClaims.CLAIM_CLIENT_ID, jwtProperties.clientId),
            requiredStringClaim(CommonJwtClaims.CLAIM_SESSION_ID),
            requiredStringClaim(CommonJwtClaims.CLAIM_TOKEN_FAMILY_ID),
            nonNegativeNumberClaim(CommonJwtClaims.CLAIM_TOKEN_ROTATION),
            exactValueClaim(CommonJwtClaims.CLAIM_TOKEN_USE, CommonJwtClaims.TOKEN_USE_REFRESH)
        )

    @Bean("accessTokenDecoder")
    fun accessTokenDecoder(
        jwkSource: JWKSource<SecurityContext>,
        jwtProperties: IdentityJwtProperties,
        @Qualifier("accessTokenValidator") validator: OAuth2TokenValidator<Jwt>
    ): JwtDecoder = jwtDecoder(jwkSource, jwtProperties, validator)

    @Bean("refreshTokenDecoder")
    fun refreshTokenDecoder(
        jwkSource: JWKSource<SecurityContext>,
        jwtProperties: IdentityJwtProperties,
        @Qualifier("refreshTokenValidator") validator: OAuth2TokenValidator<Jwt>
    ): JwtDecoder = jwtDecoder(jwkSource, jwtProperties, validator)

    private fun jwtDecoder(
        jwkSource: JWKSource<SecurityContext>,
        jwtProperties: IdentityJwtProperties,
        validator: OAuth2TokenValidator<Jwt>
    ): JwtDecoder {
        val algorithms = jwtProperties.signing.keys
            .map { JWSAlgorithm.parse(it.algorithmName()) }
            .toSet()
        return NimbusJwtDecoder.withJwkSource(jwkSource)
            .jwtProcessorCustomizer { processor ->
                (processor as DefaultJWTProcessor<SecurityContext>).apply {
                    jwsKeySelector = JWSVerificationKeySelector(algorithms, jwkSource)
                    jwsTypeVerifier = JOSEObjectTypeVerifier { _, _ -> }
                }
            }
            .build()
            .also { it.setJwtValidator(validator) }
    }

    private fun toJwk(keySpec: IdentityJwtProperties.KeySpec): JWK = when (keySpec.type) {
        IdentityJwtProperties.KeyType.HS -> {
            val secretBytes = decodeSecret(requireNotNull(keySpec.secret))
            require(secretBytes.size >= minKeyLength(keySpec.requireMacAlgorithm().name)) {
                "iam.security.jwt.signing.keys[${keySpec.id}] 的 Base64 解码长度不足，无法满足 ${keySpec.requireMacAlgorithm().name} 的最小密钥要求"
            }
            OctetSequenceKey.Builder(secretBytes)
                .keyID(keySpec.id)
                .algorithm(JWSAlgorithm.parse(keySpec.algorithmName()))
                .build()
        }

        IdentityJwtProperties.KeyType.RSA -> {
            val publicKey = parseRsaPublicKey(requireNotNull(keySpec.publicKey))
            val privateKey = parseRsaPrivateKey(requireNotNull(keySpec.privateKey))
            RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keySpec.id)
                .algorithm(JWSAlgorithm.parse(keySpec.algorithmName()))
                .build()
        }

        IdentityJwtProperties.KeyType.EC -> {
            val publicKey = parseEcPublicKey(requireNotNull(keySpec.publicKey))
            val privateKey = parseEcPrivateKey(requireNotNull(keySpec.privateKey))
            ECKey.Builder(Curve.forECParameterSpec(publicKey.params), publicKey)
                .privateKey(privateKey)
                .keyID(keySpec.id)
                .algorithm(JWSAlgorithm.parse(keySpec.algorithmName()))
                .build()
        }
    }

    private fun decodeSecret(secret: String): ByteArray = try {
        Base64.getDecoder().decode(secret.trim())
    } catch (ex: IllegalArgumentException) {
        throw IllegalStateException("JWT secret 必须是合法的 Base64 字符串", ex)
    }

    private fun minKeyLength(macAlgorithm: String): Int = when (macAlgorithm) {
        "HS384" -> 48
        "HS512" -> 64
        else -> 32
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

    private fun requiredStringClaim(name: String): OAuth2TokenValidator<Jwt> =
        JwtClaimValidator<Any>(name) { it is String && it.isNotBlank() }

    private fun requiredInstantClaim(name: String): OAuth2TokenValidator<Jwt> =
        JwtClaimValidator<Any>(name) { it is Instant }

    private fun nonNegativeNumberClaim(name: String): OAuth2TokenValidator<Jwt> =
        JwtClaimValidator<Any>(name) { it is Number && it.toLong() >= 0 }

    private fun exactValueClaim(name: String, expectedValue: String): OAuth2TokenValidator<Jwt> =
        JwtClaimValidator<Any>(name) { it == expectedValue }

    private fun parseRsaPublicKey(pem: String): RSAPublicKey = KeyFactory.getInstance("RSA")
        .generatePublic(X509EncodedKeySpec(decodePem(pem))) as RSAPublicKey

    private fun parseRsaPrivateKey(pem: String): RSAPrivateKey = KeyFactory.getInstance("RSA")
        .generatePrivate(PKCS8EncodedKeySpec(decodePem(pem))) as RSAPrivateKey

    private fun parseEcPublicKey(pem: String): ECPublicKey = KeyFactory.getInstance("EC")
        .generatePublic(X509EncodedKeySpec(decodePem(pem))) as ECPublicKey

    private fun parseEcPrivateKey(pem: String): ECPrivateKey = KeyFactory.getInstance("EC")
        .generatePrivate(PKCS8EncodedKeySpec(decodePem(pem))) as ECPrivateKey

    private fun decodePem(pem: String): ByteArray = Base64.getMimeDecoder().decode(
        pem.lineSequence()
            .map(String::trim)
            .filter { it.isNotEmpty() && !it.startsWith("-----") }
            .joinToString("")
    )
}
