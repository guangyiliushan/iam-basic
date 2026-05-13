package top.guangyiliushan.iam.identity.internal.application.command

import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import top.guangyiliushan.iam.identity.IdentityErrorCode
import top.guangyiliushan.iam.identity.internal.application.port.out.AccessTokenPort
import top.guangyiliushan.iam.identity.internal.application.port.out.JtiReplayProtectionPort
import top.guangyiliushan.iam.identity.internal.application.port.out.RefreshTokenPort
import top.guangyiliushan.iam.identity.internal.application.port.out.RefreshTokenSessionCachePort
import top.guangyiliushan.iam.identity.internal.domain.model.TokenUse
import top.guangyiliushan.iam.identity.internal.infrastructure.config.IdentityJwtProperties
import top.guangyiliushan.iam.shared.error.BusinessException
import java.time.Instant
import java.util.UUID

@Service
class AuthCmdService(
    private val accessTokenPort: AccessTokenPort,
    private val refreshTokenPort: RefreshTokenPort,
    private val refreshTokenSessionCachePort: RefreshTokenSessionCachePort,
    private val jtiReplayProtectionPort: JtiReplayProtectionPort,
    private val jwtProperties: IdentityJwtProperties
) {
    private val logger = LoggerFactory.getLogger(AuthCmdService::class.java)

    data class IssueTokenPairCommand(
        val accountId: String,
        val sessionId: String = UUID.randomUUID().toString(),
        val authorities: Collection<String> = emptyList(),
        val tokenVersion: Long = 0,
        val deviceId: String? = null,
        val tokenFamilyId: String? = null,
        val refreshRotation: Long = 0
    )

    data class AuthTokenBundle(
        val accountId: String,
        val sessionId: String,
        val deviceId: String?,
        val clientId: String,
        val tokenType: String,
        val authorities: Set<String>,
        val tokenVersion: Long,
        val accessToken: String,
        val accessTokenId: String,
        val accessTokenIssuedAt: Instant,
        val accessTokenExpiresAt: Instant,
        val refreshToken: String,
        val refreshTokenId: String,
        val refreshTokenIssuedAt: Instant,
        val refreshTokenExpiresAt: Instant,
        val tokenFamilyId: String,
        val refreshRotation: Long
    )
    fun issueTokenPair(command: IssueTokenPairCommand): AuthTokenBundle {
        val accessToken = accessTokenPort.generateAccessToken(
            accountId = command.accountId,
            sessionId = command.sessionId,
            authorities = command.authorities,
            tokenVersion = command.tokenVersion,
            deviceId = command.deviceId
        )
        val accessClaims = accessTokenPort.validateAccessToken(accessToken)
            ?: throw BusinessException(IdentityErrorCode.TOKEN_VALIDATION_FAILED)
        val refreshToken = refreshTokenPort.generateRefreshToken(
            accountId = command.accountId,
            sessionId = command.sessionId,
            deviceId = command.deviceId,
            tokenFamilyId = command.tokenFamilyId,
            rotation = command.refreshRotation
        )
        val refreshClaims = refreshTokenPort.validateRefreshToken(refreshToken)
            ?: throw BusinessException(IdentityErrorCode.REFRESH_TOKEN_VALIDATION_FAILED)
        refreshTokenSessionCachePort.save(
            RefreshTokenSessionCachePort.RefreshTokenSessionRecord(
                accountId = refreshClaims.accountId,
                sessionId = refreshClaims.sessionId,
                deviceId = refreshClaims.deviceId,
                tokenFamilyId = refreshClaims.tokenFamilyId,
                currentTokenId = refreshClaims.tokenId,
                currentTokenHash = refreshTokenPort.hashRefreshToken(refreshToken),
                currentRotation = refreshClaims.rotation,
                clientId = refreshClaims.clientId,
                issuedAt = refreshClaims.issuedAt,
                expiresAt = refreshClaims.expiresAt
            )
        )
        return AuthTokenBundle(
            accountId = command.accountId,
            sessionId = command.sessionId,
            deviceId = command.deviceId,
            clientId = refreshClaims.clientId,
            tokenType = "Bearer",
            authorities = accessClaims.authorities,
            tokenVersion = accessClaims.tokenVersion,
            accessToken = accessToken,
            accessTokenId = accessClaims.tokenId,
            accessTokenIssuedAt = accessClaims.issuedAt,
            accessTokenExpiresAt = accessClaims.expiresAt,
            refreshToken = refreshToken,
            refreshTokenId = refreshClaims.tokenId,
            refreshTokenIssuedAt = refreshClaims.issuedAt,
            refreshTokenExpiresAt = refreshClaims.expiresAt,
            tokenFamilyId = refreshClaims.tokenFamilyId,
            refreshRotation = refreshClaims.rotation
        )
    }

    fun refresh(refreshToken: String): AuthTokenBundle {
        val claims = refreshTokenPort.validateRefreshToken(refreshToken)
            ?: throw BusinessException(IdentityErrorCode.INVALID_REFRESH_TOKEN)
        val replayAccepted = jtiReplayProtectionPort.registerIfAbsent(
            JtiReplayProtectionPort.ReplayJtiRegistration(
                tokenId = claims.tokenId,
                tokenUse = TokenUse.REFRESH,
                subject = claims.accountId,
                sessionId = claims.sessionId,
                expiresAt = claims.expiresAt,
                ttlBuffer = jwtProperties.replayDetectionTtlBuffer
            )
        )
        if (!replayAccepted) {
            logger.warn("security_event=refresh_jti_replay_detected accountId={} sessionId={} tokenId={} familyId={}", claims.accountId, claims.sessionId, claims.tokenId, claims.tokenFamilyId)
            throw BusinessException(IdentityErrorCode.REFRESH_TOKEN_REPLAY_DETECTED)
        }
        val nextRefreshToken = refreshTokenPort.generateRefreshToken(
            accountId = claims.accountId,
            sessionId = claims.sessionId,
            deviceId = claims.deviceId,
            tokenFamilyId = claims.tokenFamilyId,
            rotation = claims.rotation + 1
        )
        val nextClaims = refreshTokenPort.validateRefreshToken(nextRefreshToken)
            ?: throw BusinessException(IdentityErrorCode.REFRESH_TOKEN_ROTATION_VALIDATION_FAILED)
        return when (
            val rotationResult = refreshTokenSessionCachePort.rotate(
                RefreshTokenSessionCachePort.RefreshTokenRotationCommand(
                    presentedTokenId = claims.tokenId,
                    presentedTokenHash = refreshTokenPort.hashRefreshToken(refreshToken),
                    tokenFamilyId = claims.tokenFamilyId,
                    nextTokenId = nextClaims.tokenId,
                    nextTokenHash = refreshTokenPort.hashRefreshToken(nextRefreshToken),
                    nextRotation = nextClaims.rotation,
                    rotatedAt = Instant.now(),
                    nextExpiresAt = nextClaims.expiresAt,
                    reuseDetectionWindow = jwtProperties.refreshReuseDetectionWindow
                )
            )
        ) {
            is RefreshTokenSessionCachePort.RefreshTokenRotationResult.Rotated -> {
                val accessToken = accessTokenPort.generateAccessToken(claims.accountId, claims.sessionId, emptyList(), 0, claims.deviceId)
                val accessClaims = accessTokenPort.validateAccessToken(accessToken)
                    ?: throw BusinessException(IdentityErrorCode.ACCESS_TOKEN_ROTATION_VALIDATION_FAILED)
                buildTokenBundle(claims, accessClaims, accessToken, nextClaims, nextRefreshToken)
            }
            is RefreshTokenSessionCachePort.RefreshTokenRotationResult.ReuseDetected -> {
                logger.warn("security_event=refresh_token_reuse_detected accountId={} sessionId={} tokenId={} familyId={}", claims.accountId, claims.sessionId, claims.tokenId, claims.tokenFamilyId)
                refreshTokenSessionCachePort.revokeFamily(claims.tokenFamilyId, Instant.now(), "reuse_detected")
                throw BusinessException(IdentityErrorCode.REFRESH_TOKEN_REUSE_DETECTED)
            }
            is RefreshTokenSessionCachePort.RefreshTokenRotationResult.HashMismatch -> throw BusinessException(IdentityErrorCode.INVALID_REFRESH_TOKEN)
            is RefreshTokenSessionCachePort.RefreshTokenRotationResult.Revoked -> throw BusinessException(IdentityErrorCode.REFRESH_TOKEN_REVOKED)
            is RefreshTokenSessionCachePort.RefreshTokenRotationResult.NotFound -> throw BusinessException(IdentityErrorCode.REFRESH_TOKEN_REVOKED)
        }
    }

    private fun buildTokenBundle(
        refreshClaims: RefreshTokenPort.RefreshTokenClaims,
        accessClaims: AccessTokenPort.AccessTokenClaims,
        accessToken: String,
        nextRefreshClaims: RefreshTokenPort.RefreshTokenClaims,
        nextRefreshToken: String
    ): AuthTokenBundle {
        return AuthTokenBundle(
            accountId = refreshClaims.accountId,
            sessionId = refreshClaims.sessionId,
            deviceId = refreshClaims.deviceId,
            clientId = refreshClaims.clientId,
            tokenType = "Bearer",
            authorities = accessClaims.authorities,
            tokenVersion = accessClaims.tokenVersion,
            accessToken = accessToken,
            accessTokenId = accessClaims.tokenId,
            accessTokenIssuedAt = accessClaims.issuedAt,
            accessTokenExpiresAt = accessClaims.expiresAt,
            refreshToken = nextRefreshToken,
            refreshTokenId = nextRefreshClaims.tokenId,
            refreshTokenIssuedAt = nextRefreshClaims.issuedAt,
            refreshTokenExpiresAt = nextRefreshClaims.expiresAt,
            tokenFamilyId = nextRefreshClaims.tokenFamilyId,
            refreshRotation = nextRefreshClaims.rotation
        )
    }
}