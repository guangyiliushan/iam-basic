package top.guangyiliushan.iam.identity.internal.domain.port.out

import java.time.Instant

interface RefreshTokenPort {

    fun generateRefreshToken(
        accountId: String,
        sessionId: String,
        deviceId: String? = null,
        tokenFamilyId: String? = null,
        rotation: Long = 0
    ): String

    fun validateRefreshToken(token: String): RefreshTokenClaims?

    fun hashRefreshToken(token: String): String

    data class RefreshTokenClaims(
        val accountId: String,
        val issuer: String,
        val audiences: Set<String>,
        val sessionId: String,
        val tokenId: String,
        val issuedAt: Instant,
        val expiresAt: Instant,
        val deviceId: String?,
        val tokenFamilyId: String,
        val rotation: Long,
        val clientId: String,
        val tokenUse: String
    )
}