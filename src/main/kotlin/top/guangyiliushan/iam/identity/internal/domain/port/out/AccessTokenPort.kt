package top.guangyiliushan.iam.identity.internal.domain.port.out

import java.time.Instant

interface AccessTokenPort {

    fun generateAccessToken(
        accountId: String,
        sessionId: String,
        authorities: Collection<String> = emptyList(),
        tokenVersion: Long = 0,
        deviceId: String? = null
    ): String

    fun validateAccessToken(token: String): AccessTokenClaims?

    /**
     * 仅在签名、类型、时效和业务 claims 全部通过后提取主体信息。
     */
    fun extractAccountId(token: String): String?

    data class AccessTokenClaims(
        val accountId: String,
        val issuer: String,
        val audiences: Set<String>,
        val sessionId: String,
        val tokenId: String,
        val issuedAt: Instant,
        val expiresAt: Instant,
        val authorities: Set<String>,
        val tokenVersion: Long,
        val deviceId: String?,
        val clientId: String,
        val tokenUse: String
    )
}