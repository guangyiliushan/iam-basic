package top.guangyiliushan.iam.shared.error

import org.springframework.http.HttpStatus

class BusinessException(
    val errorCode: ErrorCode,
    customMessage: String? = null
) : RuntimeException(customMessage ?: errorCode.message) {

    val code: Int = errorCode.code
    val httpStatus: HttpStatus = errorCode.httpStatus

    companion object {
        fun withFormat(errorCode: ErrorCode, vararg args: Any): BusinessException {
            return BusinessException(
                errorCode,
                String.format(errorCode.message, *args)
            )
        }

        fun of(code: Int, message: String, httpStatus: HttpStatus): BusinessException {
            return BusinessException(object : ErrorCode {
                override val code = code
                override val message = message
                override val httpStatus = httpStatus
            })
        }
    }
}