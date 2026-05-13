package top.guangyiliushan.iam.identity

import org.springframework.http.HttpStatus
import top.guangyiliushan.iam.shared.error.ErrorCode

enum class IdentityErrorCode(
    override val code: Int,
    override val message: String,
    override val httpStatus: HttpStatus
) : ErrorCode {

    // 400 - 请求参数错误
    USERNAME_BLANK(40001001, "用户名不能为空", HttpStatus.BAD_REQUEST),
    PASSWORD_BLANK(40001002, "密码不能为空", HttpStatus.BAD_REQUEST),
    PASSWORD_TOO_WEAK(40001003, "密码强度不足", HttpStatus.BAD_REQUEST),

    // 401 - 认证失败
    INVALID_CREDENTIALS(40101001, "用户名或密码错误", HttpStatus.UNAUTHORIZED),
    ACCOUNT_DISABLED(40101002, "账号已被禁用", HttpStatus.UNAUTHORIZED),
    ACCOUNT_NOT_ACTIVATED(40101003, "账号未激活", HttpStatus.UNAUTHORIZED),
    INVALID_REFRESH_TOKEN(40101004, "刷新令牌无效", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_REVOKED(40101005, "刷新令牌已失效", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_REPLAY_DETECTED(40101006, "检测到刷新令牌重放", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_REUSE_DETECTED(40101007, "检测到刷新令牌复用", HttpStatus.UNAUTHORIZED),

    // 409 - 冲突
    USERNAME_ALREADY_EXISTS(40901001, "用户名已存在", HttpStatus.CONFLICT),
    EMAIL_ALREADY_EXISTS(40901002, "邮箱已被注册", HttpStatus.CONFLICT),

    // 500 - 服务器错误
    PASSWORD_ENCRYPTION_FAILED(50001001, "密码加密失败", HttpStatus.INTERNAL_SERVER_ERROR),
    TOKEN_VALIDATION_FAILED(50001011, "访问令牌生成后校验失败", HttpStatus.INTERNAL_SERVER_ERROR),
    REFRESH_TOKEN_VALIDATION_FAILED(50001012, "刷新令牌生成后校验失败", HttpStatus.INTERNAL_SERVER_ERROR),
    REFRESH_TOKEN_ROTATION_VALIDATION_FAILED(50001013, "刷新令牌轮换后校验失败", HttpStatus.INTERNAL_SERVER_ERROR),
    ACCESS_TOKEN_ROTATION_VALIDATION_FAILED(50001014, "访问令牌轮换后校验失败", HttpStatus.INTERNAL_SERVER_ERROR),

}