package top.guangyiliushan.iam.identity.internal.infrastructure.security.jwt

import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.stereotype.Component
import top.guangyiliushan.iam.identity.internal.application.port.out.RefreshTokenPort
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
        return encoder.encode(JwtEncoderParameters.from(buildHeaders(), claims)).tokenValue
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
    ): JwtClaimsSet = JwtClaimsSet.builder()
        .issuer(jwtProperties.issuer)
        .subject(accountId)
        .audience(listOf(jwtProperties.refreshToken.audience))
        .issuedAt(issuedAt)
        .expiresAt(expiresAt)
        .id(UUID.randomUUID().toString())
        .claim(CLAIM_CLIENT_ID, jwtProperties.clientId)
        .claim(CLAIM_SESSION_ID, sessionId)
        .claim(CLAIM_TOKEN_FAMILY_ID, tokenFamilyId ?: UUID.randomUUID().toString())
        .claim(CLAIM_TOKEN_ROTATION, rotation)
        .claim(CLAIM_TOKEN_USE, TOKEN_USE_REFRESH)
        .apply {
            if (!deviceId.isNullOrBlank()) {
                claim(CLAIM_DEVICE_ID, deviceId)
            }
        }
        .build()

    private fun buildHeaders(): JwsHeader = JwsHeader.with(jwtProperties.macAlgorithm)
        .type(jwtProperties.refreshToken.type)
        .keyId(jwtProperties.keyId)
        .build()

    private fun toClaims(jwt: Jwt): RefreshTokenPort.RefreshTokenClaims? = with(CommonJwtClaims) {
        val common = jwt.readCommonClaims(
            sessionClaimName = CLAIM_SESSION_ID,
            clientIdClaimName = CLAIM_CLIENT_ID,
            tokenUseClaimName = CLAIM_TOKEN_USE,
            deviceIdClaimName = CLAIM_DEVICE_ID
        ) ?: return null
        val tokenFamilyId = jwt.getClaimAsString(CLAIM_TOKEN_FAMILY_ID) ?: return null
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
            rotation = jwt.getClaim<Number>(CLAIM_TOKEN_ROTATION)?.toLong() ?: 0,
            clientId = common.clientId,
            tokenUse = common.tokenUse
        )
    }

    private companion object {
        const val CLAIM_CLIENT_ID = "client_id"
        const val CLAIM_DEVICE_ID = "did"
        const val CLAIM_SESSION_ID = "sid"
        const val CLAIM_TOKEN_FAMILY_ID = "fid"
        const val CLAIM_TOKEN_ROTATION = "rot"
        const val CLAIM_TOKEN_USE = "token_use"
        const val TOKEN_USE_REFRESH = "refresh"
    }
}