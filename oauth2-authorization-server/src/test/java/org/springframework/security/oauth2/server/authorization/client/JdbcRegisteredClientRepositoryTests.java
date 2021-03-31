package org.springframework.security.oauth2.server.authorization.client;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StreamUtils;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * JDBC-backed registered client repository tests
 *
 * @author Rafal Lewczuk
 * @since 0.1.2
 */
public class JdbcRegisteredClientRepositoryTests {

	private final String ROOT = "/org/springframework/security/oauth2/server/authorization/client/";
	private final List<String> SCRIPTS = Arrays.asList("clients.ddl", "clients_testdata.sql");

	private DriverManagerDataSource dataSource;
	private JdbcRegisteredClientRepository repository;

	@Before
	public void setup() throws Exception {
		dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName("org.hsqldb.jdbcDriver");
		dataSource.setUrl("jdbc:hsqldb:mem:oauthtest");
		dataSource.setUsername("sa");
		dataSource.setPassword("");

		JdbcTemplate jdbc = new JdbcTemplate(dataSource);

		// execute scripts
		for (String script : SCRIPTS) {
			try (InputStream is = JdbcRegisteredClientRepositoryTests.class.getResourceAsStream(ROOT + script)) {
				assertThat(is).isNotNull().describedAs("Cannot open resource file: " + ROOT + script);
				String ddls = StreamUtils.copyToString(is, Charset.defaultCharset());
				for (String ddl : ddls.split(";\n")) {
					if (!ddl.trim().isEmpty()) {
						jdbc.execute(ddl);
					}
				}
			}
		}

		repository = new JdbcRegisteredClientRepository();
		repository.setDataSource(dataSource);
		repository.afterPropertiesSet();
	}

	@After
	public void destroyDatabase() {
		new JdbcTemplate(dataSource).execute("SHUTDOWN");
	}

	@Test
	public void whenNullQueryThenThrow() {
		assertThatThrownBy(() -> repository.setClientsByIdQuery(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientsByIdQuery cannot be null nor empty");
	}

	@Test
	public void whenSetNullCollSeparatorThenThrow() {
		assertThatThrownBy(() -> repository.setCollSeparator(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("collSeparator cannot be null nor empty");
	}

	@Test
	public void whenSetNullRegisteredRowMapperThenThrow() {
		assertThatThrownBy(() -> repository.setRegisteredClientRowMapper(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClientRowMapper cannot be null");
	}

	@Test
	public void whenClientEntryIsEnabledThenReturnRegisteredClient() {
		RegisteredClient client = repository.findById("test");
		assertThat(client).isNotNull();
		assertThat(client.getId()).isEqualTo("test");
		assertThat(client.getClientSecret()).isEqualTo("test");
		assertThat(client.getScopes().contains("test")).isTrue();
		assertThat(client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)).isTrue();
		assertThat(client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.BASIC)).isTrue();
		assertThat(client.getRedirectUris().contains("https://test")).isTrue();
		assertThat(client.getClientSettings().requireProofKey()).isFalse();
		assertThat(client.getClientSettings().requireUserConsent()).isFalse();
		assertThat(client.getTokenSettings().accessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(5));
		assertThat(client.getTokenSettings().refreshTokenTimeToLive()).isEqualTo(Duration.ofMinutes(10));
		assertThat(client.getTokenSettings().reuseRefreshTokens()).isTrue();
	}

	@Test
	public void whenClientEntryIsDisabledThenReturnNull() {
		assertThat(repository.findById("test2")).isNull();
		assertThat(repository.findByClientId("test2")).isNull();
	}

	@Test
	public void whenClientEntryContainsMultipleSeparatedCollectionItems() {
		RegisteredClient c = repository.findByClientId("test3");
		assertThat(c).isNotNull();
		assertThat(c.getScopes().size()).isEqualTo(2);
		assertThat(c.getScopes().contains("openid")).isTrue();
		assertThat(c.getScopes().contains("test")).isTrue();
		assertThat(c.getRedirectUris().size()).isEqualTo(2);
		assertThat(c.getRedirectUris().contains("https://test")).isTrue();
		assertThat(c.getRedirectUris().contains("https://test2")).isTrue();
		assertThat(c.getAuthorizationGrantTypes().size()).isEqualTo(2);
		assertThat(c.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)).isTrue();
		assertThat(c.getAuthorizationGrantTypes().contains(AuthorizationGrantType.PASSWORD)).isTrue();
	}

	@Test
	public void whenBadlyFormedUrlShouldThrow() {
		assertThatThrownBy(() -> repository.findByClientId("test4"))
				.isInstanceOf(IllegalArgumentException.class);
	}
}
