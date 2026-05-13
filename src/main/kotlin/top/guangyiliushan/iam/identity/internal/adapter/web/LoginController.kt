package top.guangyiliushan.iam.identity.internal.adapter.web

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
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
        val loginResult = LoginResult(
            userId = result.accountId.toLong(),
            accessToken = result.accessToken,
            refreshToken = result.refreshToken,
            accessTokenExpiresIn = (result.accessTokenExpiresAt.epochSecond - result.accessTokenIssuedAt.epochSecond)
        )
        return ResponseEntity.ok(ApiResponse.success(loginResult))
    }
}
