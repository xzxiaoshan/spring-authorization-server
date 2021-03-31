package org.springframework.security.oauth2.server.authorization;

import org.springframework.security.oauth2.core.OAuth2TokenType;

/**
 * @program: spring-authorization-server
 * @description: provide a JDBC implementation of OAuth2AuthorizationService
 * @author: Zhangzp
 * @create: 2021-03-31 11:25
 **/
public class JdbcOAuth2AuthorizationService implements OAuth2AuthorizationService {


	@Override
	public void save(OAuth2Authorization authorization) {

	}

	@Override
	public void remove(OAuth2Authorization authorization) {

	}

	@Override
	public OAuth2Authorization findById(String id) {
		return null;
	}

	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
		return null;
	}
}
