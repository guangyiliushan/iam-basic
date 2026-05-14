package top.guangyiliushan.iam.identity.internal.infrastructure.security.jwt

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.stereotype.Component

@Component
class JwtAuthenticationConverter : Converter<Jwt, AbstractAuthenticationToken> {

    override fun convert(jwt: Jwt): AbstractAuthenticationToken {
        val authorities = extractAuthorities(jwt)
        return JwtAuthenticationToken(jwt, authorities, jwt.subject)
    }

    private fun extractAuthorities(jwt: Jwt): Collection<GrantedAuthority> {
        val authorities = linkedSetOf<GrantedAuthority>()

        CommonJwtClaims.parseAuthorities(jwt.getClaimAsString(CommonJwtClaims.CLAIM_SCOPE))
            .forEach { scope -> authorities.add(SimpleGrantedAuthority("SCOPE_$scope")) }

        jwt.getClaimAsStringList("authorities")
            ?.map(String::trim)
            ?.filter(String::isNotEmpty)
            ?.forEach { authority -> authorities.add(SimpleGrantedAuthority(authority)) }

        // 如果没有找到任何权限，至少添加一个基本的认证角色
        if (authorities.isEmpty()) {
            authorities.add(SimpleGrantedAuthority("ROLE_AUTHENTICATED"))
        }

        return authorities
    }
}
