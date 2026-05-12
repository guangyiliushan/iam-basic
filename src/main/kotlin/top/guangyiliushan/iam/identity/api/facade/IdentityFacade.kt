package top.guangyiliushan.iam.identity.api.facade

import org.springframework.modulith.NamedInterface
import top.guangyiliushan.iam.identity.api.dto.command.LoginCmd
import top.guangyiliushan.iam.identity.api.dto.command.RegisterCmd
import top.guangyiliushan.iam.identity.api.dto.result.LoginResult
import top.guangyiliushan.iam.identity.api.dto.result.RegisterResult

@NamedInterface(value = ["api"], propagate = true)
interface IdentityFacade {

    /**
     * 用户登录
     *
     * @param cmd 登录命令，包含用户名和密码
     * @return 登录结果，包含用户ID
     * @throws top.guangyiliushan.iam.shared.error.BusinessException 当凭证无效时抛出 INVALID_CREDENTIALS
     */
    fun login(cmd: LoginCmd): LoginResult

    /**
     * 用户注册
     *
     * @param cmd 注册命令，包含用户名和密码
     * @return 注册结果，包含用户ID
     * @throws top.guangyiliushan.iam.shared.error.BusinessException 当用户名已存在时抛出 USERNAME_ALREADY_EXISTS
     */
    fun register(cmd: RegisterCmd): RegisterResult
}