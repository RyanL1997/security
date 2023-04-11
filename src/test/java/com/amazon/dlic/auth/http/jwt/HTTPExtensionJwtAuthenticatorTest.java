package com.amazon.dlic.auth.http.jwt;

import com.google.common.io.BaseEncoding;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.hc.core5.http.HttpHeaders;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class HTTPExtensionJwtAuthenticatorTest {
    final static byte[] secretKeyBytes = new byte[1024];
    final static String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
    final static SecretKey secretKey;

    static {
        new SecureRandom().nextBytes(secretKeyBytes);
        secretKey = Keys.hmacShaKeyFor(secretKeyBytes);
    }

    @Test
    public void testNoKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                null,
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy"));

        Assert.assertNull(credentials);
    }

    @Test
    public void testEmptyKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                "",
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy"));

        Assert.assertNull(credentials);
    }

    @Test
    public void testBadKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(new byte[]{1,3,3,4,3,6,7,8,3,10}),
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy"));

        Assert.assertNull(credentials);
    }

    @Test
    public void testTokenMissing() throws Exception {

        HTTPExtensionJwtAuthenticator jwtAuth = new HTTPExtensionJwtAuthenticator(BaseEncoding.base64().encode(secretKeyBytes),claimsEncryptionKey);
        Map<String, String> headers = new HashMap<String, String>();

        AuthCredentials credentials = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);

        Assert.assertNull(credentials);
    }

    @Test
    public void testInvalid() throws Exception {

        String jwsToken = "123invalidtoken..";

        HTTPExtensionJwtAuthenticator jwtAuth = new HTTPExtensionJwtAuthenticator(BaseEncoding.base64().encode(secretKeyBytes), claimsEncryptionKey);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);
        Assert.assertNull(credentials);
    }

    @Test
    public void testBearer() throws Exception {

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").setAudience("myaud").signWith(secretKey, SignatureAlgorithm.HS512).compact();

        HTTPExtensionJwtAuthenticator jwtAuth = new HTTPExtensionJwtAuthenticator(BaseEncoding.base64().encode(secretKeyBytes), claimsEncryptionKey);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);

        AuthCredentials credentials = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
        Assert.assertEquals(2, credentials.getAttributes().size());
    }

    @Test
    public void testBearerWrongPosition() throws Exception {

        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).build();

        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(secretKey, SignatureAlgorithm.HS512).compact();

        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken + "Bearer " + " 123");

        AuthCredentials credentials = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()), null);

        Assert.assertNull(credentials);
    }


    @Test
    public void testBasicAuthHeader() throws Exception {
        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKeyBytes)).build();
        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);

        String basicAuth = BaseEncoding.base64().encode("user:password".getBytes(StandardCharsets.UTF_8));
        Map<String, String> headers = Collections.singletonMap(HttpHeaders.AUTHORIZATION, "Basic " + basicAuth);

        AuthCredentials credentials = jwtAuth.extractCredentials(new FakeRestRequest(headers, Collections.emptyMap()), null);
        Assert.assertNull(credentials);
    }

    @Test
    public void testRoles() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(secretKeyBytes),
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy").claim("roles", "role1,role2"));

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(2, credentials.getBackendRoles().size());
    }

    @Test
    public void testNullClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(secretKeyBytes),
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy").claim("roles", null));

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testNonStringClaim() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(secretKeyBytes),
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy").claim("roles", 123L));

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(1, credentials.getBackendRoles().size());
        Assert.assertTrue( credentials.getBackendRoles().contains("123"));
    }

    @Test
    public void testRolesMissing() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(secretKeyBytes),
                claimsEncryptionKey,
                Jwts.builder().setSubject("Leonard McCoy"));

        Assert.assertNotNull(credentials);
        Assert.assertEquals("Leonard McCoy", credentials.getUsername());
        Assert.assertEquals(0, credentials.getBackendRoles().size());
    }

    @Test
    public void testWrongSubjectKey() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(secretKeyBytes),
                claimsEncryptionKey,
                Jwts.builder().claim("roles", "role1,role2").claim("asub", "Dr. Who"));

        Assert.assertNull(credentials);
    }

    @Test
    public void testExp() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(secretKeyBytes),
                claimsEncryptionKey,
                Jwts.builder().setSubject("Expired").setExpiration(new Date(100)));

        Assert.assertNull(credentials);
    }

    @Test
    public void testNbf() throws Exception {

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(secretKeyBytes),
                claimsEncryptionKey,
                Jwts.builder().setSubject("Expired").setNotBefore(new Date(System.currentTimeMillis()+(1000*36000))));

        Assert.assertNull(credentials);
    }

    @Test
    public void testRolesArray() throws Exception {

        JwtBuilder builder = Jwts.builder()
                .setPayload("{"+
                        "\"sub\": \"John Doe\","+
                        "\"roles\": [\"a\",\"b\",\"3rd\"]"+
                        "}");

        final AuthCredentials credentials = extractCredentialsFromJwtHeader(
                BaseEncoding.base64().encode(secretKeyBytes),
                claimsEncryptionKey,
                builder);

        Assert.assertNotNull(credentials);
        Assert.assertEquals("John Doe", credentials.getUsername());
        Assert.assertEquals(3, credentials.getBackendRoles().size());
        Assert.assertTrue(credentials.getBackendRoles().contains("a"));
        Assert.assertTrue(credentials.getBackendRoles().contains("b"));
        Assert.assertTrue(credentials.getBackendRoles().contains("3rd"));
    }

    /** extracts a default user credential from a request header */
    private AuthCredentials extractCredentialsFromJwtHeader(
            final String signingKey,
            final String encryptionKey,
            final JwtBuilder jwtBuilder) {
        final String jwsToken = jwtBuilder.signWith(secretKey, SignatureAlgorithm.HS512).compact();
        final HTTPExtensionJwtAuthenticator jwtAuth = new HTTPExtensionJwtAuthenticator(signingKey, encryptionKey);
        final Map<String, String> headers = Map.of("Authorization", jwsToken);
        return jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<>()), null);
    }
}
