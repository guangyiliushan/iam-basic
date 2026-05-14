package top.guangyiliushan.iam.identity.internal.adapter.web

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import top.guangyiliushan.iam.identity.api.dto.command.LoginCmd
import top.guangyiliushan.iam.identity.api.dto.result.LoginResult
import top.guangyiliushan.iam.identity.internal.application.command.LoginCmdService
import top.guangyiliushan.iam.shared.api.ApiResponse

@Tag(name = "IAM")
@RestController
@RequestMapping("/api/iam")
class LoginController(
    private val loginCmdService: LoginCmdService
) {
    @PostMapping("/login", version = "1.0")
    fun login(@Valid @RequestBody request: LoginCmd): ResponseEntity<ApiResponse<LoginResult>> {
        val result = loginCmdService.login(
            username = request.username,
            password = request.password
        )
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, result.refreshTokenCookie.toString())
            .body(ApiResponse.success(result.toApiResult()))
    }

    @PostMapping("/refresh", version = "1.0")
    fun refresh(httpServletRequest: HttpServletRequest): ResponseEntity<ApiResponse<LoginResult>> =
        loginCmdService.refresh(httpServletRequest).let { result ->
            ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.refreshTokenCookie.toString())
                .body(ApiResponse.success(result.toApiResult()))
        }

    @PostMapping("/logout", version = "1.0")
    fun logout(
        @AuthenticationPrincipal jwt: Jwt?,
        httpServletRequest: HttpServletRequest
    ): ResponseEntity<ApiResponse<String>> {
        val clearCookie = loginCmdService.logout(jwt, httpServletRequest)
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, clearCookie.toString())
            .body(ApiResponse.success("logout success"))
    }

    private fun LoginCmdService.LoginCommandResult.toApiResult(): LoginResult = LoginResult(
        userId = userId,
        accessToken = accessToken,
        accessTokenExpiresIn = accessTokenExpiresIn
    )
}
