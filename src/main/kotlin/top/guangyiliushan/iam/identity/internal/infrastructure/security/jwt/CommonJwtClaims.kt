package top.guangyiliushan.iam.identity.internal.infrastructure.security.jwt

import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwsHeader
import top.guangyiliushan.iam.identity.internal.infrastructure.config.IdentityJwtProperties
import java.time.Instant

object CommonJwtClaims {
    const val CLAIM_CLIENT_ID = "client_id"
    const val CLAIM_DEVICE_ID = "did"
    const val CLAIM_SCOPE = "scope"
    const val CLAIM_SESSION_ID = "sid"
    const val CLAIM_TOKEN_FAMILY_ID = "fid"
    const val CLAIM_TOKEN_ROTATION = "rot"
    const val CLAIM_TOKEN_USE = "token_use"
    const val CLAIM_TOKEN_VERSION = "ver"
    const val TOKEN_USE_ACCESS = "access"
    const val TOKEN_USE_REFRESH = "refresh"

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

    internal fun buildJwsHeader(jwtProperties: IdentityJwtProperties, tokenType: String): JwsHeader =
        JwsHeader.with(jwtProperties.signing.activeKey().jwsAlgorithm())
            .type(tokenType)
            .keyId(jwtProperties.signing.activeKeyId)
            .build()

    internal fun buildBaseClaims(
        jwtProperties: IdentityJwtProperties,
        audience: String,
        accountId: String,
        sessionId: String,
        issuedAt: Instant,
        expiresAt: Instant,
        tokenId: String,
        tokenUse: String,
        deviceId: String?
    ): JwtClaimsSet.Builder = JwtClaimsSet.builder()
        .issuer(jwtProperties.issuer)
        .subject(accountId)
        .audience(listOf(audience))
        .issuedAt(issuedAt)
        .expiresAt(expiresAt)
        .id(tokenId)
        .claim(CLAIM_CLIENT_ID, jwtProperties.clientId)
        .claim(CLAIM_SESSION_ID, sessionId)
        .claim(CLAIM_TOKEN_USE, tokenUse)
        .apply {
            if (!deviceId.isNullOrBlank()) {
                claim(CLAIM_DEVICE_ID, deviceId)
            }
        }

    internal fun normalizeAuthorities(authorities: Collection<String>): Set<String> =
        authorities.map(String::trim).filter(String::isNotEmpty).toSet()

    internal fun parseAuthorities(scope: String?): Set<String> =
        scope?.split(' ')?.map(String::trim)?.filter(String::isNotEmpty)?.toSet() ?: emptySet()

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
