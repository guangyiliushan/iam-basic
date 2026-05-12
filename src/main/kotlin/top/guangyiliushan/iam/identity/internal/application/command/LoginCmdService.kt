package top.guangyiliushan.iam.identity.internal.application.command

import org.springframework.stereotype.Service
import top.guangyiliushan.iam.identity.api.IdentityErrorCode
import top.guangyiliushan.iam.identity.internal.application.assembler.LoginAssembler
import top.guangyiliushan.iam.identity.internal.domain.port.out.PasswordHashPort
import top.guangyiliushan.iam.identity.internal.domain.repository.AccountRepository
import top.guangyiliushan.iam.shared.error.BusinessException

@Service
class LoginCmdService(
    private val accountRepository: AccountRepository,
    private val passwordHashPort: PasswordHashPort
) {
    fun login(username: String, password: String): Long {
        val account = accountRepository.findByUsername(username)
            ?: throw BusinessException(IdentityErrorCode.INVALID_CREDENTIALS)

        if (!passwordHashPort.verify(password, account.password)) {
            throw BusinessException(IdentityErrorCode.INVALID_CREDENTIALS)
        }

        return LoginAssembler.toResult(account)
    }
}
