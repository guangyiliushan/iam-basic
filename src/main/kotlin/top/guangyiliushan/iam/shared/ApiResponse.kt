package top.guangyiliushan.iam.shared

import org.springframework.http.HttpStatus

/**
 * 统一 API 响应包装类
 */
data class ApiResponse<T>(
    val success: Boolean,
    val data: T? = null,
    val message: String? = null,
    val code: Int? = null
) {
    companion object {
        fun <T> success(data: T): ApiResponse<T> =
            ApiResponse(success = true, data = data, code = HttpStatus.OK.value())

        fun <T> success(data: T, message: String): ApiResponse<T> =
            ApiResponse(success = true, data = data, message = message, code = HttpStatus.OK.value())

        fun <T> error(message: String): ApiResponse<T> =
            ApiResponse(success = false, message = message, code = HttpStatus.INTERNAL_SERVER_ERROR.value())

        // 业务异常通常由 GlobalExceptionHandler 传入具体的 ErrorCode.code
        fun <T> error(code: Int, message: String): ApiResponse<T> =
            ApiResponse(success = false, message = message, code = code)
    }
}