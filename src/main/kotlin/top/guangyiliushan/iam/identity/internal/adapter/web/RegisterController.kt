package top.guangyiliushan.iam.identity.internal.adapter.web

import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import top.guangyiliushan.iam.identity.api.dto.command.RegisterCmd
import top.guangyiliushan.iam.identity.api.dto.result.RegisterResult
import top.guangyiliushan.iam.identity.internal.application.command.RegisterCmdService
import top.guangyiliushan.iam.shared.ApiResponse

@Tag(name = "IAM")
@RestController
@RequestMapping("/api/iam")
class RegisterController(
    private val registerCmdService: RegisterCmdService
) {
    @PostMapping("/register", version = "1.0")
    fun register(@Valid @RequestBody request: RegisterCmd): ResponseEntity<ApiResponse<RegisterResult>> {
        val result = registerCmdService.register(
            username = request.username,
            password = request.password
        )
        val registerResult = RegisterResult(userId = result)
        return ResponseEntity.ok(ApiResponse.success(registerResult))
    }
}
