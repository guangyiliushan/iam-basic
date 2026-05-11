package top.guangyiliushan.iam.identity.internal.adapter.facade

import org.springframework.stereotype.Service
import top.guangyiliushan.iam.identity.api.dto.command.LoginCmd
import top.guangyiliushan.iam.identity.api.dto.command.RegisterCmd
import top.guangyiliushan.iam.identity.api.dto.result.LoginResult
import top.guangyiliushan.iam.identity.api.dto.result.RegisterResult
import top.guangyiliushan.iam.identity.api.facade.IdentityFacade
import top.guangyiliushan.iam.identity.internal.application.command.LoginCmdService
import top.guangyiliushan.iam.identity.internal.application.command.RegisterCmdService

@Service
class IdentityFacadeImpl(
    private val loginCmdService: LoginCmdService,
    private val registerCmdService: RegisterCmdService
) : IdentityFacade {

    override fun login(cmd: LoginCmd): LoginResult {
        val userId = loginCmdService.login(
            username = cmd.username,
            password = cmd.password
        )
        return LoginResult(userId = userId)
    }

    override fun register(cmd: RegisterCmd): RegisterResult {
        val userId = registerCmdService.register(
            username = cmd.username,
            password = cmd.password
        )
        return RegisterResult(userId = userId)
    }
}