package top.guangyiliushan.iam.identity.internal.infrastructure.security.jwt

import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.stereotype.Component
import top.guangyiliushan.iam.identity.internal.domain.port.out.RefreshTokenPort
import top.guangyiliushan.iam.identity.internal.infrastructure.config.IdentityJwtProperties
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID

@Component
class RefreshTokenManager(
    private val encoder: JwtEncoder,
    @Qualifier("refreshTokenDecoder") private val decoder: JwtDecoder,
    private val clock: Clock,
    private val jwtProperties: IdentityJwtProperties,
) : RefreshTokenPort {

    override fun generateRefreshToken(
        accountId: String,
        sessionId: String,
        deviceId: String?,
        tokenFamilyId: String?,
        rotation: Long
    ): String {
        val issuedAt = Instant.now(clock)
        val expiresAt = issuedAt.plus(jwtProperties.refreshToken.ttl)
        val claims = buildClaimsSet(accountId, sessionId, issuedAt, expiresAt, deviceId, tokenFamilyId, rotation)
        return encoder.encode(
            JwtEncoderParameters.from(CommonJwtClaims.buildJwsHeader(jwtProperties, jwtProperties.refreshToken.type), claims)
        ).tokenValue
    }

    override fun validateRefreshToken(token: String): RefreshTokenPort.RefreshTokenClaims? = try {
        toClaims(decoder.decode(token))
    } catch (_: JwtException) {
        null
    }

    override fun hashRefreshToken(token: String): String = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.UTF_8)))

    private fun buildClaimsSet(
        accountId: String,
        sessionId: String,
        issuedAt: Instant,
        expiresAt: Instant,
        deviceId: String?,
        tokenFamilyId: String?,
        rotation: Long
    ): JwtClaimsSet = CommonJwtClaims.buildBaseClaims(
        jwtProperties = jwtProperties,
        audience = jwtProperties.refreshToken.audience,
        accountId = accountId,
        sessionId = sessionId,
        issuedAt = issuedAt,
        expiresAt = expiresAt,
        tokenId = UUID.randomUUID().toString(),
        tokenUse = CommonJwtClaims.TOKEN_USE_REFRESH,
        deviceId = deviceId
    )
        .claim(CommonJwtClaims.CLAIM_TOKEN_FAMILY_ID, tokenFamilyId ?: UUID.randomUUID().toString())
        .claim(CommonJwtClaims.CLAIM_TOKEN_ROTATION, rotation)
        .build()

    private fun toClaims(jwt: Jwt): RefreshTokenPort.RefreshTokenClaims? = with(CommonJwtClaims) {
        val common = jwt.readCommonClaims(
            sessionClaimName = CommonJwtClaims.CLAIM_SESSION_ID,
            clientIdClaimName = CommonJwtClaims.CLAIM_CLIENT_ID,
            tokenUseClaimName = CommonJwtClaims.CLAIM_TOKEN_USE,
            deviceIdClaimName = CommonJwtClaims.CLAIM_DEVICE_ID
        ) ?: return null
        val tokenFamilyId = jwt.getClaimAsString(CommonJwtClaims.CLAIM_TOKEN_FAMILY_ID) ?: return null
        RefreshTokenPort.RefreshTokenClaims(
            accountId = common.accountId,
            issuer = common.issuer,
            audiences = common.audiences,
            sessionId = common.sessionId,
            tokenId = common.tokenId,
            issuedAt = common.issuedAt,
            expiresAt = common.expiresAt,
            deviceId = common.deviceId,
            tokenFamilyId = tokenFamilyId,
            rotation = jwt.getClaim<Number>(CommonJwtClaims.CLAIM_TOKEN_ROTATION)?.toLong() ?: 0,
            clientId = common.clientId,
            tokenUse = common.tokenUse
        )
    }
}
