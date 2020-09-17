package org.javaboy.vhr.config;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 * 该类的作用：判断当前用户是否具备当前访问请求地址相对于的角色
 */
@Component
public class MenuAccessDecisionManager implements AccessDecisionManager {
    @Override
    // Collection<ConfigAttribute>即 MenuWithRowFilter中getAttributes()的返回值
    public void decide(Authentication auth, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        for (ConfigAttribute configAttribute : configAttributes) {
            // 获取所需要的角色信息(当前请求地址所需的角色之一)
            String needRole = configAttribute.getAttribute();
            // 如果是未匹配的上的情况
            if ("ROLE_LOGIN".equals(needRole)) {
                // 如果当前用户是匿名的情况
                if (auth instanceof AnonymousAuthenticationToken) {
                    throw new AccessDeniedException("尚未登录，请先登录！");
                } else {
                    return;
                }
            }
            // 获取当前登录用户的角色
            Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
            for (GrantedAuthority authority : authorities) {
                if (authority.getAuthority().equals(needRole)) {
                    return;
                }
            }
        }
        throw new AccessDeniedException("权限不足，请联系管理员！");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
