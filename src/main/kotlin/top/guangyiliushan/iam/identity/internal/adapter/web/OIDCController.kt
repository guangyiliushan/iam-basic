package top.guangyiliushan.iam.identity.internal.adapter.web

import jakarta.validation.Valid
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import top.guangyiliushan.iam.identity.api.dto.result.OpenIdConfigurationResult
import top.guangyiliushan.iam.shared.api.ApiResponse

@RestController
@RequestMapping("/.well-known")
class OIDCController {
    @GetMapping("/openid-configuration")
    fun openidConfiguration(): ResponseEntity<ApiResponse<OpenIdConfigurationResult>> {
        return ResponseEntity.ok(
            ApiResponse.success(
                OpenIdConfigurationResult(
                    issuer = "",
                    authorizationEndpoint = "",
                    tokenEndpoint = "",
                    userinfoEndpoint = "",
                    jwksUri = ""
                )
            )
        )
    }
}
