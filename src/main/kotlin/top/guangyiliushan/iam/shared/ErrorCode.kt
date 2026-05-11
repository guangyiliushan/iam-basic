package top.guangyiliushan.iam.shared

import org.springframework.http.HttpStatus

interface ErrorCode {
    val code: Int
    val message: String
    val httpStatus: HttpStatus
}