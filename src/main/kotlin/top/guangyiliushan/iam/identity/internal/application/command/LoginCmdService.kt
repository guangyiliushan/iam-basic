package top.guangyiliushan.iam.identity.internal.application.command

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.ResponseCookie
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.stereotype.Service
import top.guangyiliushan.iam.identity.IdentityErrorCode
import top.guangyiliushan.iam.identity.internal.application.assembler.LoginAssembler
import top.guangyiliushan.iam.identity.internal.domain.port.out.PasswordHashPort
import top.guangyiliushan.iam.identity.internal.domain.repository.AccountRepository
import top.guangyiliushan.iam.identity.internal.infrastructure.config.IdentityJwtProperties
import top.guangyiliushan.iam.identity.internal.infrastructure.security.jwt.CommonJwtClaims
import top.guangyiliushan.iam.shared.error.BusinessException
import java.time.Duration

@Service
class LoginCmdService(
    private val accountRepository: AccountRepository,
    private val passwordHashPort: PasswordHashPort,
    private val authCmdService: AuthCmdService,
    private val jwtProperties: IdentityJwtProperties
) {
    fun login(username: String, password: String): LoginCommandResult {
        val account = accountRepository.findByUsername(username)
            ?: throw BusinessException(IdentityErrorCode.INVALID_CREDENTIALS)
        if (!passwordHashPort.verify(password, account.password)) {
            throw BusinessException(IdentityErrorCode.INVALID_CREDENTIALS)
        }
        val userId = LoginAssembler.toResult(account)
        return buildLoginCommandResult(
            AuthCmdService.IssueTokenPairCommand(
                accountId = userId.toString()
            )
        )
    }

    fun refresh(httpServletRequest: HttpServletRequest): LoginCommandResult =
        buildLoginCommandResult(authCmdService.refresh(requireRefreshToken(httpServletRequest)))

    fun logout(jwt: Jwt?, httpServletRequest: HttpServletRequest): ResponseCookie {
        val currentSessionId = jwt?.getClaimAsString(CommonJwtClaims.CLAIM_SESSION_ID)
        val refreshToken = readRefreshTokenCookie(httpServletRequest)
        val sessionId = currentSessionId ?: refreshToken?.let(authCmdService::resolveSessionId)
        sessionId?.let(authCmdService::logout)
        return clearRefreshTokenCookie()
    }

    private fun buildLoginCommandResult(command: AuthCmdService.IssueTokenPairCommand): LoginCommandResult =
        buildLoginCommandResult(authCmdService.issueTokenPair(command))

    private fun buildLoginCommandResult(bundle: AuthCmdService.AuthTokenBundle): LoginCommandResult =
        LoginCommandResult(
            userId = bundle.accountId.toLong(),
            accessToken = bundle.accessToken,
            accessTokenExpiresIn = bundle.accessTokenExpiresAt.epochSecond - bundle.accessTokenIssuedAt.epochSecond,
            refreshTokenCookie = buildRefreshTokenCookie(bundle.refreshToken)
        )

    private fun requireRefreshToken(httpServletRequest: HttpServletRequest): String =
        readRefreshTokenCookie(httpServletRequest)
            ?.takeIf(String::isNotBlank)
            ?: throw BusinessException(IdentityErrorCode.INVALID_REFRESH_TOKEN)

    private fun buildRefreshTokenCookie(
        value: String,
        maxAge: Duration = jwtProperties.refreshTokenCookie.effectiveMaxAge(jwtProperties.refreshToken.ttl)
    ): ResponseCookie {
        val cookie = jwtProperties.refreshTokenCookie
        val builder = ResponseCookie.from(cookie.name, value)
            .path(cookie.path)
            .domain(cookie.domain)
            .httpOnly(cookie.httpOnly)
            .secure(cookie.secure)
            .maxAge(maxAge)
        cookie.sameSiteAttribute()?.let(builder::sameSite)
        return builder.build()
    }

    private fun clearRefreshTokenCookie(): ResponseCookie = buildRefreshTokenCookie("", Duration.ZERO)

    private fun readRefreshTokenCookie(httpServletRequest: HttpServletRequest): String? =
        httpServletRequest.cookies
            ?.firstOrNull { it.name == jwtProperties.refreshTokenCookie.name }
            ?.value

    data class LoginCommandResult(
        val userId: Long,
        val accessToken: String,
        val accessTokenExpiresIn: Long,
        val refreshTokenCookie: ResponseCookie
    )
}
