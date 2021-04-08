package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.util.Assert;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.*;
import java.util.stream.Stream;

/**
 * JDBC-backed registered client repository
 *
 * @author Rafal Lewczuk
 * @since 0.1.2
 */
public class JdbcRegisteredClientRepository extends JdbcDaoSupport implements RegisteredClientRepository {

	private static final Map<String, AuthorizationGrantType> AUTHORIZATION_GRANT_TYPE_MAP;
	private static final Map<String, ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHOD_MAP;

	public static final String DEF_CLIENTS_BY_ID_QUERY = "select * from oauth2_registered_client where client_id = ? and enabled = true";

	private static final String DEF_COLL_SEPARATOR = "\\|";

	private String clientsByIdQuery;
	private String clientsByClientIdQuery;
	private String collSeparator;

	private RowMapper<RegisteredClient> registeredClientRowMapper;

	public JdbcRegisteredClientRepository() {
		this.clientsByIdQuery = DEF_CLIENTS_BY_ID_QUERY;
		this.clientsByClientIdQuery = DEF_CLIENTS_BY_ID_QUERY;
		this.collSeparator = DEF_COLL_SEPARATOR;
		this.registeredClientRowMapper = this::defaultRegisteredClientRowMapper;
	}

	@Override
	public RegisteredClient findById(String id) {
		List<RegisteredClient> lst = getJdbcTemplate().query(clientsByIdQuery, registeredClientRowMapper, id);
		return lst.size() == 1 ? lst.get(0) : null;
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		List<RegisteredClient> lst = getJdbcTemplate().query(clientsByClientIdQuery, registeredClientRowMapper, clientId);
		return lst.size() == 1 ? lst.get(0) : null;
	}

	private RegisteredClient defaultRegisteredClientRowMapper(ResultSet rs, int rownum) throws SQLException {

		Stream<String> scopes = Arrays.stream(rs.getString("scopes").trim()
				.split(this.collSeparator)).map(String::trim);
		Stream<AuthorizationGrantType> authGrantTypes = Arrays.stream(rs.getString("auth_grant_types")
				.trim().split(this.collSeparator))
				.map(String::trim).map(AUTHORIZATION_GRANT_TYPE_MAP::get);
		Stream<ClientAuthenticationMethod> clientAuthMethods = Arrays.stream(rs.getString("client_auth_methods")
				.trim().split(this.collSeparator))
				.map(String::trim).map(CLIENT_AUTHENTICATION_METHOD_MAP::get);
		Stream<String> redirectUris = Arrays.stream(rs.getString("redirect_uris").trim()
				.split(this.collSeparator)).map(String::trim);
		RegisteredClient.Builder builder = RegisteredClient.withId(rs.getString("client_id"))
				.clientId(rs.getString("client_id"))
				.clientSecret(rs.getString("client_secret"))
				.scopes(coll -> scopes.forEach(coll::add))
				.authorizationGrantTypes(coll -> authGrantTypes.forEach(coll::add))
				.clientAuthenticationMethods(coll -> clientAuthMethods.forEach(coll::add))
				.redirectUris(coll -> redirectUris.forEach(coll::add));

		RegisteredClient rc = builder.build();

		TokenSettings ts = rc.getTokenSettings();
		ts.accessTokenTimeToLive(Duration.ofMillis(rs.getLong("access_token_ttl")));
		ts.refreshTokenTimeToLive(Duration.ofMillis(rs.getLong("refresh_token_ttl")));
		ts.reuseRefreshTokens(rs.getBoolean("refresh_token_reuse"));

		ClientSettings cs = rc.getClientSettings();
		cs.requireProofKey(rs.getBoolean("require_pkce"));
		cs.requireUserConsent(rs.getBoolean("require_consent"));

		return rc;
	}

	/**
	 * Allows default query string for finding client by internal ID to be overridden.
	 *
	 * @param clientsByIdQuery SQL query string to set
	 */
	public void setClientsByIdQuery(String clientsByIdQuery) {
		Assert.hasText(clientsByIdQuery, "clientsByIdQuery cannot be null nor empty");
		this.clientsByIdQuery = clientsByIdQuery;
	}

	/**
	 * Allows default query string for finding client by internal ID to be overridden.
	 *
	 * @param clientsByClientIdQuery SQL query string to set
	 */
	public void setClientsByClientIdQuery(String clientsByClientIdQuery) {
		Assert.hasText(clientsByClientIdQuery, "clientsByClientIdQuery cannot be null nor empty");
		this.clientsByClientIdQuery = clientsByClientIdQuery;
	}

	/**
	 * Allows changing of {@link RegisteredClient} row mapper implementation
	 *
	 * @param registeredClientRowMapper new row mapper
	 */
	public void setRegisteredClientRowMapper(RowMapper<RegisteredClient> registeredClientRowMapper) {
		Assert.notNull(registeredClientRowMapper, "registeredClientRowMapper cannot be null");
		this.registeredClientRowMapper = registeredClientRowMapper;
	}

	public void setCollSeparator(String collSeparator) {
		Assert.hasText(collSeparator, "collSeparator cannot be null nor empty");
		this.collSeparator = collSeparator;
	}

	static {
		Map<String, AuthorizationGrantType> am = new HashMap<>();
		for (AuthorizationGrantType a : Arrays.asList(
				AuthorizationGrantType.AUTHORIZATION_CODE,
				AuthorizationGrantType.REFRESH_TOKEN,
				AuthorizationGrantType.CLIENT_CREDENTIALS,
				AuthorizationGrantType.PASSWORD,
				AuthorizationGrantType.IMPLICIT
		)) {
			am.put(a.getValue(), a);
		}
		AUTHORIZATION_GRANT_TYPE_MAP = Collections.unmodifiableMap(am);

		Map<String, ClientAuthenticationMethod> cm = new HashMap<>();
		for (ClientAuthenticationMethod c : Arrays.asList(
				ClientAuthenticationMethod.NONE,
				ClientAuthenticationMethod.BASIC,
				ClientAuthenticationMethod.POST)) {
			cm.put(c.getValue(), c);
		}
		CLIENT_AUTHENTICATION_METHOD_MAP = Collections.unmodifiableMap(cm);
	}
}
