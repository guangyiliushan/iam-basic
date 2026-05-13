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
import top.guangyiliushan.iam.identity.internal.application.port.out.AccessTokenPort
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

    override fun generateAccessToken(
        accountId: String,
        sessionId: String,
        authorities: Collection<String>,
        tokenVersion: Long,
        deviceId: String?
    ): String {
        val issuedAt = Instant.now(clock)
        val expiresAt = issuedAt.plus(jwtProperties.accessToken.ttl)
        val normalizedAuthorities = normalizeAuthorities(authorities)
        val claims = JwtClaimsSet.builder()
            .issuer(jwtProperties.issuer) // 签发者
            .subject(accountId) // 主题
            .audience(listOf(jwtProperties.accessToken.audience))   // 受众
            .issuedAt(issuedAt) // 签发时间
            .expiresAt(expiresAt) // 过期时间
            .id(UUID.randomUUID().toString()) // 唯一标识
            .claim(CLAIM_CLIENT_ID, jwtProperties.clientId) // 客户端ID
            .claim(CLAIM_SESSION_ID, sessionId) // 会话ID
            .claim(CLAIM_TOKEN_VERSION, tokenVersion) // token版本
            .claim(CLAIM_TOKEN_USE, TOKEN_USE_ACCESS) // token使用
            .apply { // 添加自定义属性, 这里添加了 scope 属性标识用户权限范围, 这里添加了 deviceId 属性标识设备ID
                if (normalizedAuthorities.isNotEmpty()) claim(CLAIM_SCOPE, normalizedAuthorities.joinToString(" "))
                if (!deviceId.isNullOrBlank()) claim(CLAIM_DEVICE_ID, deviceId)
            }
            .build()
        val headers = JwsHeader.with(jwtProperties.macAlgorithm)
            .type(jwtProperties.accessToken.type)
            .keyId(jwtProperties.keyId)
            .build()
        return encoder.encode(JwtEncoderParameters.from(headers, claims)).tokenValue
    }

    override fun validateAccessToken(token: String): AccessTokenPort.AccessTokenClaims? = try {
        toClaims(decoder.decode(token))
    } catch (_: JwtException) {
        null
    }

    override fun extractAccountId(token: String): String? = validateAccessToken(token)?.accountId

    private fun toClaims(jwt: Jwt): AccessTokenPort.AccessTokenClaims? = with(CommonJwtClaims) {
        val common = jwt.readCommonClaims(
            sessionClaimName = CLAIM_SESSION_ID,
            clientIdClaimName = CLAIM_CLIENT_ID,
            tokenUseClaimName = CLAIM_TOKEN_USE,
            deviceIdClaimName = CLAIM_DEVICE_ID
        ) ?: return null
        AccessTokenPort.AccessTokenClaims(
            accountId = common.accountId,
            issuer = common.issuer,
            audiences = common.audiences,
            sessionId = common.sessionId,
            tokenId = common.tokenId,
            issuedAt = common.issuedAt,
            expiresAt = common.expiresAt,
            authorities = parseAuthorities(jwt.getClaimAsString(CLAIM_SCOPE)),
            tokenVersion = jwt.getClaim<Number>(CLAIM_TOKEN_VERSION)?.toLong() ?: 0,
            deviceId = common.deviceId,
            clientId = common.clientId,
            tokenUse = common.tokenUse
        )
    }

    private fun normalizeAuthorities(authorities: Collection<String>): Set<String> =
        authorities.map(String::trim).filter(String::isNotEmpty).toSet()

    private fun parseAuthorities(scope: String?): Set<String> =
        scope?.split(' ')?.map(String::trim)?.filter(String::isNotEmpty)?.toSet() ?: emptySet()

    private companion object {
        const val CLAIM_CLIENT_ID = "client_id"
        const val CLAIM_DEVICE_ID = "did"
        const val CLAIM_SCOPE = "scope"
        const val CLAIM_SESSION_ID = "sid"
        const val CLAIM_TOKEN_USE = "token_use"
        const val CLAIM_TOKEN_VERSION = "ver"
        const val TOKEN_USE_ACCESS = "access"
    }
}