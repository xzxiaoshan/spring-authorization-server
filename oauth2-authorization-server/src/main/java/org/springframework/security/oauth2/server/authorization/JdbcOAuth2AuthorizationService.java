package org.springframework.security.oauth2.server.authorization;


import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.*;
import java.security.Principal;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * provide a JDBC implementation of OAuth2AuthorizationService
 *
 * @author: Zhangzp
 * @create: 2021-03-31 11:25
 **/
public class JdbcOAuth2AuthorizationService implements OAuth2AuthorizationService {
	private static final String COLUMN_NAMES = "client_registration_id, "
			+ "principal_name, "
			+ "access_token_type, "
			+ "authorization_code, "
			+ "authorization_code_issued_at, "
			+ "authorization_code_expires_at, "
			+ "authorized_grant_types,"
			+ "access_token_value, "
			+ "access_token_issued_at, "
			+ "access_token_expires_at, "
			+ "access_token_scopes, "
			+ "refresh_token_value, "
			+ "refresh_token_issued_at,"
			+ "refresh_token_expires_at,"
			+ "additional_information";
	private static final String TABLE_NAME = "oauth2_authorized_client";
	private static final String PK_FILTER = "client_registration_id = ? AND principal_name = ?";
	private static final String ACCESS_TOKEN_FILTER = "access_token_value = ?";
	private static final String REFRESH_TOKEN_FILTER = "refresh_token_value = ?";
	private static final String ADDITIONAL_INFORMATION_FILTER = "additional_information like concat('%',concat(?,'%'))";
	private static final String AUTHORIZATION_CODE_FILTER = "authorization_code = ?";
	private static final String LOAD_AUTHORIZED_CLIENT_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + PK_FILTER;
	private static final String SAVE_AUTHORIZED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
	private static final String REMOVE_AUTHORIZED_CLIENT_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + PK_FILTER;
	private static final String UPDATE_AUTHORIZED_CLIENT_SQL = "UPDATE " + TABLE_NAME
			+ " SET access_token_type = ?, authorization_code = ? ,"
			+ " authorization_code_issued_at = ?, authorization_code_expires_at = ?, authorized_grant_types = ?,"
			+ " access_token_value = ?, access_token_issued_at = ?,"
			+ " access_token_expires_at = ?, access_token_scopes = ?,"
			+ " refresh_token_value = ?, refresh_token_issued_at = ?, refresh_token_expires_at = ?, "
			+ " additional_information = ? "
			+ " WHERE " + PK_FILTER;
	private static final String LOAD_BY_ACCESS_TOKEN_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + ACCESS_TOKEN_FILTER;
	private static final String LOAD_BY_REFRESH_TOKEN_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + REFRESH_TOKEN_FILTER;
	private static final String LOAD_BY_ADDITIONAL_INFORMATION_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + ADDITIONAL_INFORMATION_FILTER;
	private static final String LOAD_BY_AUTHORIZATION_CODE_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + AUTHORIZATION_CODE_FILTER;

	protected final JdbcOperations jdbcOperations;
	protected RowMapper<OAuth2Authorization> authorizedClientRowMapper;
	protected Function<OAuth2AuthorizationHolder, List<SqlParameterValue>> authorizedClientParametersMapper;

	/**
	 * Constructs a {@code JdbcOAuth2AuthorizationService} using the provided
	 * parameters.
	 *
	 * @param jdbcOperations             the JDBC operations
	 * @param registeredClientRepository the repository of client registrations
	 */
	public JdbcOAuth2AuthorizationService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.authorizedClientRowMapper = new OAuth2AuthorizationRowMapper(registeredClientRepository);
		this.authorizedClientParametersMapper = new OAuth2AuthorizationParametersMapper();
	}

	private OAuth2Authorization loadAuthorizationByClientIdAndPrincipleName(String clientRegistrationId, String principalName) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		SqlParameterValue[] parameters = new SqlParameterValue[]{
				new SqlParameterValue(Types.VARCHAR, clientRegistrationId),
				new SqlParameterValue(Types.VARCHAR, principalName)};
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		List<OAuth2Authorization> result = this.jdbcOperations.query(LOAD_AUTHORIZED_CLIENT_SQL, pss,
				this.authorizedClientRowMapper);
		return !result.isEmpty() ? result.get(0) : null;
	}

	@Override
	public void save(OAuth2Authorization oAuth2Authorization) {
		Assert.notNull(oAuth2Authorization, "oAuth2Authorization cannot be null");
		boolean existsAuthorizedClient = null != this.loadAuthorizationByClientIdAndPrincipleName(
				oAuth2Authorization.getRegisteredClientId(),
				oAuth2Authorization.getPrincipalName());
		if (existsAuthorizedClient) {
			updateAuthorization(oAuth2Authorization);
		} else {
			try {
				insertAuthorization(oAuth2Authorization);
			} catch (DuplicateKeyException ex) {
				updateAuthorization(oAuth2Authorization);
			}
		}
	}

	private void updateAuthorization(OAuth2Authorization oAuth2Authorization) {
		List<SqlParameterValue> parameters = this.authorizedClientParametersMapper
				.apply(new OAuth2AuthorizationHolder(oAuth2Authorization));
		SqlParameterValue clientRegistrationIdParameter = parameters.remove(0);
		SqlParameterValue principalNameParameter = parameters.remove(0);
		parameters.add(clientRegistrationIdParameter);
		parameters.add(principalNameParameter);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(UPDATE_AUTHORIZED_CLIENT_SQL, pss);
	}

	private void insertAuthorization(OAuth2Authorization oAuth2Authorization) {
		List<SqlParameterValue> parameters = this.authorizedClientParametersMapper
				.apply(new OAuth2AuthorizationHolder(oAuth2Authorization));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(SAVE_AUTHORIZED_CLIENT_SQL, pss);
	}

	@Override
	public void remove(OAuth2Authorization oAuth2Authorization) {
		Assert.notNull(oAuth2Authorization, "oAuth2Authorization cannot be null");
		String registeredClientId = oAuth2Authorization.getRegisteredClientId();
		String principalName = oAuth2Authorization.getPrincipalName();
		Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		SqlParameterValue[] parameters = new SqlParameterValue[]{
				new SqlParameterValue(Types.VARCHAR, registeredClientId),
				new SqlParameterValue(Types.VARCHAR, principalName)};
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		this.jdbcOperations.update(REMOVE_AUTHORIZED_CLIENT_SQL, pss);
	}

	@Override
	public OAuth2Authorization findById(String id) {
		//do nothing
		return null;
	}

	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		Assert.notNull(tokenType, "tokenType cannot be empty");
		SqlParameterValue[] blobParameters = new SqlParameterValue[]{
				new SqlParameterValue(Types.BLOB, JdbcOAuth2AuthorizationService.toByte(token))
		};
		SqlParameterValue[] stringParameters = new SqlParameterValue[]{
				new SqlParameterValue(Types.VARCHAR, token)
		};
		PreparedStatementSetter blobPreparedStatementSetter = new ArgumentPreparedStatementSetter(blobParameters);
		PreparedStatementSetter stringPreparedStatementSetter = new ArgumentPreparedStatementSetter(stringParameters);
		List<OAuth2Authorization> result = null;
		if (tokenType.equals(OAuth2TokenType.ACCESS_TOKEN)) {
			result = this.jdbcOperations.query(LOAD_BY_ACCESS_TOKEN_SQL, blobPreparedStatementSetter,
					this.authorizedClientRowMapper);
		} else if (tokenType.equals(OAuth2TokenType.REFRESH_TOKEN)) {
			result = this.jdbcOperations.query(LOAD_BY_REFRESH_TOKEN_SQL, blobPreparedStatementSetter,
					this.authorizedClientRowMapper);
		} else if (tokenType.getValue().equals(OAuth2ParameterNames.STATE)) {
			result = this.jdbcOperations.query(LOAD_BY_ADDITIONAL_INFORMATION_SQL, stringPreparedStatementSetter,
					this.authorizedClientRowMapper);
		} else if (tokenType.getValue().equals(OAuth2ParameterNames.CODE)) {
			result = this.jdbcOperations.query(LOAD_BY_AUTHORIZATION_CODE_SQL, stringPreparedStatementSetter,
					this.authorizedClientRowMapper);
		}
		return !result.isEmpty() ? result.get(0) : null;
	}

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in
	 * {@code java.sql.ResultSet} to {@link OAuth2Authorization}. The default is
	 * {@link OAuth2AuthorizationRowMapper}.
	 *
	 * @param authorizedClientRowMapper the {@link RowMapper} used for mapping the current
	 *                                  row in {@code java.sql.ResultSet} to {@link OAuth2Authorization}
	 */
	public final void setAuthorizedClientRowMapper(RowMapper<OAuth2Authorization> authorizedClientRowMapper) {
		Assert.notNull(authorizedClientRowMapper, "authorizedClientRowMapper cannot be null");
		this.authorizedClientRowMapper = authorizedClientRowMapper;
	}

	/**
	 * Sets the {@code Function} used for mapping {@link OAuth2AuthorizationHolder} to
	 * a {@code List} of {@link SqlParameterValue}. The default is
	 * {@link OAuth2AuthorizationParametersMapper}.
	 *
	 * @param authorizedClientParametersMapper the {@code Function} used for mapping
	 *                                         {@link OAuth2AuthorizationHolder} to a {@code List} of {@link SqlParameterValue}
	 */
	public final void setAuthorizedClientParametersMapper(
			Function<OAuth2AuthorizationHolder, List<SqlParameterValue>> authorizedClientParametersMapper) {
		Assert.notNull(authorizedClientParametersMapper, "authorizedClientParametersMapper cannot be null");
		this.authorizedClientParametersMapper = authorizedClientParametersMapper;
	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link OAuth2Authorization}.
	 */
	public static class OAuth2AuthorizationRowMapper implements RowMapper<OAuth2Authorization> {

		protected final RegisteredClientRepository registeredClientRepository;

		public OAuth2AuthorizationRowMapper(RegisteredClientRepository registeredClientRepository) {
			Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
			this.registeredClientRepository = registeredClientRepository;
		}

		@Override
		public OAuth2Authorization mapRow(ResultSet rs, int rowNum) throws SQLException {
			String clientId = rs.getString("client_registration_id");
			RegisteredClient registeredClient = this.registeredClientRepository
					.findByClientId(clientId);
			if (registeredClient == null) {
				throw new DataRetrievalFailureException(
						"The registeredClient with id '" + clientId + "' exists in the data source, "
								+ "however, it was not found in the RegisteredClientRepository.");
			}
			OAuth2AccessToken.TokenType tokenType = null;
			if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(rs.getString("access_token_type"))) {
				tokenType = OAuth2AccessToken.TokenType.BEARER;
			}
			String accessTokenValue = null;
			if (null != rs.getBlob("access_token_value")) {
				accessTokenValue = (String) JdbcOAuth2AuthorizationService.toObject(rs.getBlob("access_token_value"));
			}
			Instant issuedAt = null;
			if (null != rs.getTimestamp("access_token_issued_at")) {
				issuedAt = rs.getTimestamp("access_token_issued_at").toInstant();
			}
			Instant expiresAt = null;
			if (null != rs.getTimestamp("access_token_expires_at")) {
				expiresAt = rs.getTimestamp("access_token_expires_at").toInstant();
			}
			Set<String> scopes = Collections.emptySet();
			String accessTokenScopes = rs.getString("access_token_scopes");
			if (null != accessTokenScopes) {
				scopes = StringUtils.commaDelimitedListToSet(accessTokenScopes);
			}
			OAuth2AccessToken accessToken = null;
			if (null != tokenType && null != accessTokenValue && null != issuedAt && null != expiresAt) {
				accessToken = new OAuth2AccessToken(tokenType, accessTokenValue, issuedAt, expiresAt, scopes);
			}
			OAuth2RefreshToken2 refreshToken = null;
			String refreshTokenValue;
			if (null != rs.getBlob("refresh_token_value")) {
				refreshTokenValue = (String) JdbcOAuth2AuthorizationService.toObject(rs.getBlob("refresh_token_value"));
				issuedAt = null;
				Timestamp refreshTokenIssuedAt = rs.getTimestamp("refresh_token_issued_at");
				if (null != refreshTokenIssuedAt) {
					issuedAt = refreshTokenIssuedAt.toInstant();
				}
				expiresAt = null;
				Timestamp refreshTokenExpiresAt = rs.getTimestamp("refresh_token_expires_at");
				if (null != refreshTokenExpiresAt) {
					expiresAt = refreshTokenExpiresAt.toInstant();
				}
				if (null != issuedAt && null != expiresAt) {
					refreshToken = new OAuth2RefreshToken2(refreshTokenValue, issuedAt, expiresAt);
				}
			}
			String principalName = rs.getString("principal_name");
			Blob inBlob = rs.getBlob("additional_information");
			Map<String, Object> map = (Map<String, Object>) JdbcOAuth2AuthorizationService.toObject(inBlob);
			Set<AuthorizationGrantType> authorizationGrantTypes = registeredClient.getAuthorizationGrantTypes();
			List<String> collect = authorizationGrantTypes.stream().map(AuthorizationGrantType::getValue).collect(Collectors.toList());
			OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
					.authorizationGrantType(new AuthorizationGrantType(String.join(",", collect)))
					.principalName(principalName)
					.attribute(Principal.class.getName(), map.get(Principal.class.getName()))
					.attribute(OAuth2AuthorizationRequest.class.getName(), map.get(OAuth2AuthorizationRequest.class.getName()));
			if (null != rs.getString("authorization_code")
					&& null != rs.getTimestamp("authorization_code_issued_at")
					&& null != rs.getTimestamp("authorization_code_expires_at")) {
				OAuth2AuthorizationCode codeToken =
						new OAuth2AuthorizationCode(
								rs.getString("authorization_code"),
								rs.getTimestamp("authorization_code_issued_at").toInstant(),
								rs.getTimestamp("authorization_code_expires_at").toInstant());
				builder.token(codeToken);
			}
			if (null != map.get(OAuth2ParameterNames.STATE)) {
				builder.attribute(OAuth2ParameterNames.STATE, map.get(OAuth2ParameterNames.STATE));
			}
			if (null != map.get(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME)) {
				builder.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME,
						map.get(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME));
			}
			if (null != accessToken) {
				builder.accessToken(accessToken);
			}
			if (null != refreshToken) {
				builder.refreshToken(refreshToken);
			}
			return builder.build();
		}
	}


	/**
	 * The default {@code Function} that maps {@link OAuth2AuthorizationHolder} to a
	 * {@code List} of {@link SqlParameterValue}.
	 */
	public static class OAuth2AuthorizationParametersMapper
			implements Function<OAuth2AuthorizationHolder, List<SqlParameterValue>> {

		@Override
		public List<SqlParameterValue> apply(OAuth2AuthorizationHolder authorizedClientHolder) {
			OAuth2Authorization authorizedClient = authorizedClientHolder.getAuthorizedClient();
			OAuth2Authorization.Token<OAuth2AccessToken> authorizationAccessToken = authorizedClient.getAccessToken();
			OAuth2Authorization.Token<OAuth2RefreshToken> authorizationRefreshToken = authorizedClient.getRefreshToken();
			OAuth2AccessToken accessToken = null;
			OAuth2RefreshToken refreshToken = null;
			if (null != authorizationAccessToken) {
				accessToken = authorizationAccessToken.getToken();
			}
			if (null != authorizationRefreshToken) {
				refreshToken = authorizationRefreshToken.getToken();
			}
			List<SqlParameterValue> parameters = new ArrayList<>();
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorizedClient.getRegisteredClientId()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorizedClient.getPrincipalName()));
			String tokenType = null;
			String accessTokenValue = null;
			Timestamp accessTokenIssuedAt = null;
			Timestamp accessTokenExpiresAt = null;
			String accessTokenScopes = null;
			if (null != accessToken) {
				tokenType = accessToken.getTokenType().getValue();
				accessTokenValue = accessToken.getTokenValue();
				accessTokenIssuedAt = Timestamp.from(accessToken.getIssuedAt());
				accessTokenExpiresAt = Timestamp.from(accessToken.getExpiresAt());
				if (!CollectionUtils.isEmpty(accessToken.getScopes())) {
					accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.getScopes(), ",");
				}
			}
			parameters.add(new SqlParameterValue(Types.VARCHAR, tokenType));
			OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorizedClient.getToken(OAuth2AuthorizationCode.class);
			String authorizationCodeToken = null;
			Timestamp codeIssuedAt = null;
			Timestamp codeExpiresAt = null;
			if (null != authorizationCode && null != authorizationCode.getToken()) {
				authorizationCodeToken = authorizationCode.getToken().getTokenValue();
				codeIssuedAt = Timestamp.from(authorizationCode.getToken().getIssuedAt());
				codeExpiresAt = Timestamp.from(authorizationCode.getToken().getExpiresAt());
			}
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorizationCodeToken));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, codeIssuedAt));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, codeExpiresAt));
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorizedClient.getAuthorizationGrantType().getValue()));
			parameters.add(
					new SqlParameterValue(Types.BLOB, JdbcOAuth2AuthorizationService.toByte(accessTokenValue)));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, accessTokenIssuedAt));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, accessTokenExpiresAt));
			parameters.add(new SqlParameterValue(Types.VARCHAR, accessTokenScopes));
			String refreshTokenValue = null;
			Timestamp refreshTokenIssuedAt = null;
			Timestamp refreshTokenExpiresAt = null;
			if (refreshToken != null) {
				refreshTokenValue = refreshToken.getTokenValue();
				if (null != refreshToken.getIssuedAt()) {
					refreshTokenIssuedAt = Timestamp.from(refreshToken.getIssuedAt());
				}
				if (null != refreshToken.getExpiresAt()) {
					refreshTokenExpiresAt = Timestamp.from(refreshToken.getExpiresAt());
				}
			}
			parameters.add(new SqlParameterValue(Types.BLOB, JdbcOAuth2AuthorizationService.toByte(refreshTokenValue)));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, refreshTokenIssuedAt));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, refreshTokenExpiresAt));
			Map<String, Object> attributes = authorizedClient.getAttributes();
			byte[] cnb = JdbcOAuth2AuthorizationService.toByte(attributes);
			parameters.add(new SqlParameterValue(Types.BLOB, cnb));
			return parameters;
		}
	}

	private static byte[] toByte(Object attributes) {
		ByteArrayOutputStream byt = new ByteArrayOutputStream();
		try {
			ObjectOutputStream obj = new ObjectOutputStream(byt);
			obj.writeObject(attributes);

			obj.close();
			byt.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return byt.toByteArray();
	}

	private static Object toObject(Blob inBlob) {
		Object result = null;
		try {
			InputStream is = inBlob.getBinaryStream();
			BufferedInputStream bis = new BufferedInputStream(is);
			byte[] buff = new byte[(int) inBlob.length()];
			while (-1 != (bis.read(buff, 0, buff.length))) {
				ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(buff));
				result = in.readObject();
			}

			bis.close();
			is.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	/**
	 * A holder for an {@link OAuth2Authorization}
	 */
	public static final class OAuth2AuthorizationHolder {

		private final OAuth2Authorization oAuth2Authorization;

		/**
		 * Constructs an {@code OAuth2AuthorizationHolder} using the provided
		 * parameters.
		 *
		 * @param oAuth2Authorization the authorized client
		 */
		public OAuth2AuthorizationHolder(OAuth2Authorization oAuth2Authorization) {
			Assert.notNull(oAuth2Authorization, "authorizedClient cannot be null");
			this.oAuth2Authorization = oAuth2Authorization;
		}

		/**
		 * Returns the {@link OAuth2Authorization}.
		 *
		 * @return the {@link OAuth2Authorization}
		 */
		public OAuth2Authorization getAuthorizedClient() {
			return this.oAuth2Authorization;
		}
	}

}
