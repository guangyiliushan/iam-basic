package top.guangyiliushan.iam.shared

import org.springframework.http.HttpStatus

enum class CommonErrorCode(
    override val code: Int,
    override val message: String,
    override val httpStatus: HttpStatus
) : ErrorCode {
    // HTTP状态码3位-模块2位数-序号3位
    BAD_REQUEST_PARAM_FORMAT(40000001, "请求参数格式错误", HttpStatus.BAD_REQUEST),
    BAD_REQUEST_MISSING_PARAM(40000002, "缺少必选参数", HttpStatus.BAD_REQUEST),
    BAD_REQUEST_INVALID_PARAM_VALUE(40000003, "参数值非法", HttpStatus.BAD_REQUEST),
    UNAUTHORIZED_ACCESS(40100001, "未授权访问", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED_INVALID_TOKEN(40100002, "访问令牌无效", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED_TOKEN_EXPIRED(40100003, "访问令牌已过期", HttpStatus.UNAUTHORIZED),
    FORBIDDEN_INSUFFICIENT_PERMISSIONS(40300001, "权限不足", HttpStatus.FORBIDDEN),
    FORBIDDEN_ACCESS_DENIED(40300002, "禁止访问", HttpStatus.FORBIDDEN),
    NOT_FOUND_RESOURCE(40400001, "请求的资源不存在", HttpStatus.NOT_FOUND),
    CONFLICT_RESOURCE(40900001, "资源冲突", HttpStatus.CONFLICT),
    TOO_MANY_REQUESTS(42900001, "请求频率超限", HttpStatus.TOO_MANY_REQUESTS),
    INTERNAL_SERVER_ERROR(50000001, "系统内部错误", HttpStatus.INTERNAL_SERVER_ERROR),
    INTERNAL_SERVER_DB_ERROR(50000002, "数据库操作失败", HttpStatus.INTERNAL_SERVER_ERROR),
    INTERNAL_SERVER_THIRD_PARTY_ERROR(50000003, "第三方服务调用失败", HttpStatus.INTERNAL_SERVER_ERROR),
    SERVICE_UNAVAILABLE(50300001, "服务暂不可用", HttpStatus.SERVICE_UNAVAILABLE),
    GATEWAY_TIMEOUT(50400001, "网关超时", HttpStatus.GATEWAY_TIMEOUT),
}