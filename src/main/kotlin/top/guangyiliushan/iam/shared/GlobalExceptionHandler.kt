package top.guangyiliushan.iam

import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.ConstraintViolationException
import jakarta.validation.ValidationException
import org.slf4j.LoggerFactory
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.data.crossstore.ChangeSetPersister
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.HttpRequestMethodNotSupportedException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.MissingServletRequestParameterException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.util.HtmlUtils
import org.springframework.web.servlet.NoHandlerFoundException
import top.guangyiliushan.iam.shared.ApiResponse
import top.guangyiliushan.iam.shared.BusinessException
import top.guangyiliushan.iam.shared.CommonErrorCode

@RestControllerAdvice
class GlobalExceptionHandler {

    private val logger = LoggerFactory.getLogger(GlobalExceptionHandler::class.java)

    @ExceptionHandler(BusinessException::class)
    fun handleBusinessException(
        ex: BusinessException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        val status = ex.httpStatus

        return if (status.is4xxClientError) {
            clientError(status, ex.code, ex.message ?: ex.errorCode.message, request, ex)
        } else {
            serverError(ex.code, ex.message ?: "服务器内部错误", request, ex)
        }
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleMethodArgumentNotValid(
        ex: MethodArgumentNotValidException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        val errors = ex.bindingResult.fieldErrors.joinToString(", ") {
            "${it.field}:${it.defaultMessage ?: "参数不合法"}"
        }
        return clientError(
            HttpStatus.BAD_REQUEST,
            CommonErrorCode.BAD_REQUEST_INVALID_PARAM_VALUE.code,
            "参数校验失败: $errors",
            request,
            ex
        )
    }

    // 方法参数或返回值的约束校验失败
    @ExceptionHandler(ConstraintViolationException::class)
    fun handleConstraintViolation(
        ex: ConstraintViolationException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        val errors = ex.constraintViolations.joinToString(", ") {
            "${it.propertyPath}:${it.message}"
        }
        return clientError(
            HttpStatus.BAD_REQUEST,
            CommonErrorCode.BAD_REQUEST_INVALID_PARAM_VALUE.code,
            "参数校验失败: $errors",
            request,
            ex
        )
    }

    // 验证过程中的通用异常
    @ExceptionHandler(ValidationException::class)
    fun handleValidationException(
        ex: ValidationException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        // 如果是 ConstraintViolationException，会被前面的处理器捕获
        // 这里处理其他验证异常
        return clientError(
            HttpStatus.BAD_REQUEST,
            CommonErrorCode.BAD_REQUEST_INVALID_PARAM_VALUE.code,
            "参数校验失败",
            request,
            ex
        )
    }

//    @ExceptionHandler(AuthenticationException::class)
//    fun handleAuthenticationException(
//        ex: AuthenticationException,
//        request: HttpServletRequest
//    ): ResponseEntity<ApiResponse<Nothing>> {
//        return clientError(HttpStatus.UNAUTHORIZED, ErrorCode.UNAUTHORIZED.code, "未认证或认证失败", request, ex)
//    }

    @ExceptionHandler(AccessDeniedException::class)
    fun handleAccessDeniedException(
        ex: AccessDeniedException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        return clientError(
            HttpStatus.FORBIDDEN,
            CommonErrorCode.FORBIDDEN_INSUFFICIENT_PERMISSIONS.code,
            "无权限访问",
            request,
            ex
        )
    }

    // 请求的数据不存在
    @ExceptionHandler(ChangeSetPersister.NotFoundException::class)
    fun handleNotFoundException(
        ex: ChangeSetPersister.NotFoundException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        return clientError(
            HttpStatus.NOT_FOUND,
            CommonErrorCode.NOT_FOUND_RESOURCE.code,
            "资源不存在",
            request,
            ex
        )
    }

    // 请求的接口不存在
    @ExceptionHandler(NoHandlerFoundException::class)
    fun handleNoHandlerFoundException(
        ex: NoHandlerFoundException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        return clientError(
            HttpStatus.NOT_FOUND,
            CommonErrorCode.NOT_FOUND_RESOURCE.code,
            "资源不存在",
            request,
            ex
        )
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException::class)
    fun handleHttpRequestMethodNotSupportedException(
        ex: HttpRequestMethodNotSupportedException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        return clientError(
            HttpStatus.METHOD_NOT_ALLOWED,
            HttpStatus.METHOD_NOT_ALLOWED.value(),
            "请求方法不被允许",
            request,
            ex
        )
    }

    @ExceptionHandler(ResponseStatusException::class)
    fun handleResponseStatusException(
        ex: ResponseStatusException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        val status = HttpStatus.resolve(ex.statusCode.value()) ?: HttpStatus.INTERNAL_SERVER_ERROR
        val message = ex.reason?.takeIf { it.isNotBlank() }
            ?: if (status.is4xxClientError) "请求错误" else "服务器内部错误"
        return if (status.is4xxClientError) {
            clientError(status, status.value(), message, request, ex)
        } else {
            serverError(CommonErrorCode.INTERNAL_SERVER_ERROR.code, message, request, ex)
        }
    }

    @ExceptionHandler(HttpMessageNotReadableException::class)
    fun handleHttpMessageNotReadable(
        ex: HttpMessageNotReadableException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        return clientError(
            HttpStatus.BAD_REQUEST,
            CommonErrorCode.BAD_REQUEST_PARAM_FORMAT.code,
            "请求体解析失败",
            request,
            ex
        )
    }

    @ExceptionHandler(MissingServletRequestParameterException::class)
    fun handleMissingServletRequestParameter(
        ex: MissingServletRequestParameterException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        return clientError(
            HttpStatus.BAD_REQUEST,
            CommonErrorCode.BAD_REQUEST_MISSING_PARAM.code,
            "缺少必要参数: ${ex.parameterName}",
            request,
            ex
        )
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException::class)
    fun handleMethodArgumentTypeMismatch(
        ex: MethodArgumentTypeMismatchException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        return clientError(
            HttpStatus.BAD_REQUEST,
            CommonErrorCode.BAD_REQUEST_PARAM_FORMAT.code,
            "参数类型错误: ${ex.name}",
            request,
            ex
        )
    }

    @ExceptionHandler(IllegalArgumentException::class)
    fun handleIllegalArgumentException(
        ex: IllegalArgumentException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        return clientError(
            HttpStatus.BAD_REQUEST,
            CommonErrorCode.BAD_REQUEST_INVALID_PARAM_VALUE.code,
            "请求参数不合法",
            request,
            ex
        )
    }

    @ExceptionHandler(DataIntegrityViolationException::class)
    fun handleDataIntegrityViolation(
        ex: DataIntegrityViolationException,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        return clientError(
            HttpStatus.CONFLICT,
            CommonErrorCode.CONFLICT_RESOURCE.code,
            "数据冲突",
            request,
            ex
        )
    }

    @ExceptionHandler(Exception::class)
    fun handleGenericException(
        ex: Exception,
        request: HttpServletRequest
    ): ResponseEntity<ApiResponse<Nothing>> {
        return serverError(CommonErrorCode.INTERNAL_SERVER_ERROR.code, "服务器内部错误", request, ex)
    }

    private fun clientError(
        status: HttpStatus,
        code: Int,
        message: String,
        request: HttpServletRequest,
        ex: Exception? = null
    ): ResponseEntity<ApiResponse<Nothing>> {
        logger.warn("{} -> {} {}", requestSummary(request), status.value(), ex?.javaClass?.simpleName ?: "ClientError")
        return ResponseEntity.status(status).body(ApiResponse.error(code, HtmlUtils.htmlEscape(message)))
    }

    private fun serverError(
        code: Int,
        message: String,
        request: HttpServletRequest,
        ex: Exception
    ): ResponseEntity<ApiResponse<Nothing>> {
        logger.error("{} -> 500 {}", requestSummary(request), ex.javaClass.simpleName, ex)
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ApiResponse.error(code, HtmlUtils.htmlEscape(message)))
    }

    private fun requestSummary(request: HttpServletRequest): String {
        return "${request.method}${request.requestURI}"
    }
}
