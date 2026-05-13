package top.guangyiliushan.iam.identity.internal.infrastructure.security.jwt

import org.springframework.security.oauth2.jwt.Jwt
import java.time.Instant


object CommonJwtClaims {
    internal data class CommonClaims(
        val accountId: String,
        val issuer: String,
        val audiences: Set<String>,
        val sessionId: String,
        val tokenId: String,
        val issuedAt: Instant,
        val expiresAt: Instant,
        val deviceId: String?,
        val clientId: String,
        val tokenUse: String
    )
    /**
     * 从 [Jwt] 中提取通用的声明字段。
     * 如果任何必填字段缺失，则返回 null。
     *
     * @param sessionClaimName 会话 ID 的 Claim 名称 (例如 "sid")
     * @param clientIdClaimName 客户端 ID 的 Claim 名称 (例如 "client_id")
     * @param tokenUseClaimName 令牌用途的 Claim 名称 (例如 "token_use")
     * @param deviceIdClaimName 设备 ID 的 Claim 名称 (例如 "did")
     */
    internal fun Jwt.readCommonClaims(
        sessionClaimName: String,
        clientIdClaimName: String,
        tokenUseClaimName: String,
        deviceIdClaimName: String
    ): CommonClaims? {
        val accountId = subject ?: return null
        val issuer = issuer?.toString() ?: return null
        val sessionId = getClaimAsString(sessionClaimName) ?: return null
        val tokenId = id ?: return null
        val issuedAt = issuedAt ?: return null
        val expiresAt = expiresAt ?: return null
        val clientId = getClaimAsString(clientIdClaimName) ?: return null
        val tokenUse = getClaimAsString(tokenUseClaimName) ?: return null

        return CommonClaims(
            accountId = accountId,
            issuer = issuer,
            audiences = audience.toSet(),
            sessionId = sessionId,
            tokenId = tokenId,
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            deviceId = getClaimAsString(deviceIdClaimName),
            clientId = clientId,
            tokenUse = tokenUse
        )
    }
}

