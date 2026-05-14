package top.guangyiliushan.iam.identity.internal.infrastructure.security.jwt

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.stereotype.Component
import top.guangyiliushan.iam.identity.internal.domain.port.out.AccessTokenPort
import top.guangyiliushan.iam.identity.internal.infrastructure.config.IdentityJwtProperties
import java.time.Clock
import java.time.Instant
import java.util.UUID

@Component
class AccessTokenManager(
    private val encoder: JwtEncoder,
    @Qualifier("accessTokenDecoder") private val decoder: JwtDecoder,
    private val clock: Clock,
    private val jwtProperties: IdentityJwtProperties,
) : AccessTokenPort {

    private val logger = LoggerFactory.getLogger(AccessTokenManager::class.java)

    override fun generateAccessToken(
        accountId: String,
        sessionId: String,
        authorities: Collection<String>,
        tokenVersion: Long,
        deviceId: String?
    ): String {
        val issuedAt = Instant.now(clock)
        val expiresAt = issuedAt.plus(jwtProperties.accessToken.ttl)
        val normalizedAuthorities = CommonJwtClaims.normalizeAuthorities(authorities)
        val claims = CommonJwtClaims.buildBaseClaims(
            jwtProperties = jwtProperties,
            audience = jwtProperties.accessToken.audience,
            accountId = accountId,
            sessionId = sessionId,
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            tokenId = UUID.randomUUID().toString(),
            tokenUse = CommonJwtClaims.TOKEN_USE_ACCESS,
            deviceId = deviceId
        )
            .claim(CommonJwtClaims.CLAIM_TOKEN_VERSION, tokenVersion)
            .apply {
                if (normalizedAuthorities.isNotEmpty()) {
                    claim(CommonJwtClaims.CLAIM_SCOPE, normalizedAuthorities.joinToString(" "))
                }
            }
            .build()
        return encoder.encode(
            JwtEncoderParameters.from(CommonJwtClaims.buildJwsHeader(jwtProperties, jwtProperties.accessToken.type), claims)
        ).tokenValue
    }

    override fun validateAccessToken(token: String): AccessTokenPort.AccessTokenClaims? = try {
        toClaims(decoder.decode(token))
    } catch (e: JwtException) {
        logger.warn("Invalid access token: {}", e.message)
        null
    }

    override fun extractAccountId(token: String): String? = validateAccessToken(token)?.accountId

    private fun toClaims(jwt: Jwt): AccessTokenPort.AccessTokenClaims? = with(CommonJwtClaims) {
        val common = jwt.readCommonClaims(
            sessionClaimName = CommonJwtClaims.CLAIM_SESSION_ID,
            clientIdClaimName = CommonJwtClaims.CLAIM_CLIENT_ID,
            tokenUseClaimName = CommonJwtClaims.CLAIM_TOKEN_USE,
            deviceIdClaimName = CommonJwtClaims.CLAIM_DEVICE_ID
        ) ?: return null
        AccessTokenPort.AccessTokenClaims(
            accountId = common.accountId,
            issuer = common.issuer,
            audiences = common.audiences,
            sessionId = common.sessionId,
            tokenId = common.tokenId,
            issuedAt = common.issuedAt,
            expiresAt = common.expiresAt,
            authorities = CommonJwtClaims.parseAuthorities(jwt.getClaimAsString(CommonJwtClaims.CLAIM_SCOPE)),
            tokenVersion = jwt.getClaim<Number>(CommonJwtClaims.CLAIM_TOKEN_VERSION)?.toLong() ?: 0,
            deviceId = common.deviceId,
            clientId = common.clientId,
            tokenUse = common.tokenUse
        )
    }
}
