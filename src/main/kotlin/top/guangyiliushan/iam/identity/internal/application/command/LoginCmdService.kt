package top.guangyiliushan.iam.identity.internal.application.command

import org.springframework.stereotype.Service
import top.guangyiliushan.iam.identity.IdentityErrorCode
import top.guangyiliushan.iam.identity.internal.application.assembler.LoginAssembler
import top.guangyiliushan.iam.identity.internal.domain.port.out.PasswordHashPort
import top.guangyiliushan.iam.identity.internal.domain.repository.AccountRepository
import top.guangyiliushan.iam.shared.error.BusinessException

@Service
class LoginCmdService(
    private val accountRepository: AccountRepository,
    private val passwordHashPort: PasswordHashPort,
    private val authCmdService: AuthCmdService
) {
    fun login(username: String, password: String): AuthCmdService.AuthTokenBundle {
        val account = accountRepository.findByUsername(username)
            ?: throw BusinessException(IdentityErrorCode.INVALID_CREDENTIALS)
        if (!passwordHashPort.verify(password, account.password)) {
            throw BusinessException(IdentityErrorCode.INVALID_CREDENTIALS)
        }
        val userId = LoginAssembler.toResult(account)
        return authCmdService.issueTokenPair(
            AuthCmdService.IssueTokenPairCommand(
                accountId = userId.toString()
            )
        )
    }

    fun refresh(refreshToken: String): AuthCmdService.AuthTokenBundle = authCmdService.refresh(refreshToken)
}
