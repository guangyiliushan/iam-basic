package top.guangyiliushan.iam.identity.internal.adapter.web

import jakarta.validation.Valid
import top.guangyiliushan.iam.identity.api.dto.command.ExchangeAuthorizationCodeCmd
import top.guangyiliushan.iam.identity.api.dto.command.IssueClientAccessTokenCmd
import top.guangyiliushan.iam.identity.api.dto.command.RefreshAccessTokenCmd
import top.guangyiliushan.iam.identity.api.dto.command.RevokeTokenCmd
import top.guangyiliushan.iam.identity.api.dto.query.AuthorizeQuery
import top.guangyiliushan.iam.identity.api.dto.query.IntrospectTokenQuery
import top.guangyiliushan.iam.identity.api.dto.query.UserInfoQuery
import top.guangyiliushan.iam.identity.api.dto.result.AuthorizationRedirectResult
import top.guangyiliushan.iam.identity.api.dto.result.IntrospectTokenResult
import top.guangyiliushan.iam.identity.api.dto.result.JwkSetResult
import top.guangyiliushan.iam.identity.api.dto.result.OAuth2ErrorResult
import top.guangyiliushan.iam.identity.api.dto.result.TokenResult
import top.guangyiliushan.iam.identity.api.dto.result.UserInfoResult
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import top.guangyiliushan.iam.shared.api.ApiResponse

@RestController
@RequestMapping("/oauth2")
class OAuth2Controller {

    @GetMapping("/authorize", version = "1.0")
    fun authorize(
        @Valid query: AuthorizeQuery
    ): ResponseEntity<ApiResponse<AuthorizationRedirectResult>> {
        return ResponseEntity.ok(ApiResponse.success(AuthorizationRedirectResult("")))
    }

    @PostMapping("/token", version = "1.0", consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun token(
        @RequestParam("grant_type") grantType: String,
        @Valid exchangeAuthorizationCodeCmd: ExchangeAuthorizationCodeCmd,
        @Valid refreshAccessTokenCmd: RefreshAccessTokenCmd,
        @Valid issueClientAccessTokenCmd: IssueClientAccessTokenCmd
    ): ResponseEntity<ApiResponse<TokenResult>> {
        return ResponseEntity.ok(ApiResponse.success(TokenResult(
            accessToken = "",
            expiresIn = 1,
        )))
    }

    @GetMapping("/logout")
    fun logout(@RequestParam("id_token_hint") idToken: String?): ResponseEntity<Void> {
        // 处理 OIDC 登出逻辑
        return ResponseEntity.ok().build()
    }

    @GetMapping("/userinfo", version = "1.0")
    fun userinfo(
        @Valid query: UserInfoQuery
    ): ResponseEntity<ApiResponse<UserInfoResult>> {
        return ResponseEntity.ok(ApiResponse.success(UserInfoResult(
            subject = ""
        )))
    }

    @PostMapping("/introspect", version = "1.0", consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun introspect(
        @Valid query: IntrospectTokenQuery
    ): ResponseEntity<ApiResponse<IntrospectTokenResult>> {
        return ResponseEntity.ok(ApiResponse.success(IntrospectTokenResult(
            active = false,
            scope = null,
            clientId = null,
            username = null,
            tokenType = null,
            exp = null,
            iat = null
        )))
    }

    @PostMapping("/revoke", version = "1.0", consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun revoke(
        @Valid cmd: RevokeTokenCmd
    ): ResponseEntity<ApiResponse<OAuth2ErrorResult>> {
        return ResponseEntity.ok(ApiResponse.success(OAuth2ErrorResult("unsupported_grant_type", "不支持的授权类型")))
    }

    @GetMapping("/jwks", version = "1.0")
    fun jwks(): ResponseEntity<ApiResponse<JwkSetResult>> {
        return ResponseEntity.ok(ApiResponse.success(JwkSetResult(emptyList())))
    }
}
