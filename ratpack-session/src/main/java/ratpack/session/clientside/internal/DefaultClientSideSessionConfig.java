package ratpack.session.clientside.internal;

import ratpack.session.clientside.ClientSideSessionConfig;

import java.time.Duration;

/**
 * The implementation of the {@link ratpack.session.clientside.ClientSideSessionConfig} interface.
 */
public class DefaultClientSideSessionConfig implements ClientSideSessionConfig {
  private String sessionCookieName = "ratpack_session";
  private String secretToken = Long.toString(System.currentTimeMillis() / 10000);
  private String macAlgorithm = "HmacSHA1";
  private String secretKey;
  private String cipherAlgorithm = "AES/CBC/PKCS5Padding";
  private String path = "/";
  private String domain;
  private int maxSessionCookieSize = 1932;
  private Duration maxInactivityInterval = Duration.ofSeconds(120);


  @Override
  public String getSessionCookieName() {
    return sessionCookieName;
  }

  @Override
  public void setSessionCookieName(String sessionCookieName) {
    this.sessionCookieName = sessionCookieName;
  }

  @Override
  public String getSecretToken() {
    return secretToken;
  }

  @Override
  public void setSecretToken(String secretToken) {
    this.secretToken = secretToken;
  }

  @Override
  public String getMacAlgorithm() {
    return macAlgorithm;
  }

  @Override
  public void setMacAlgorithm(String macAlgorithm) {
    this.macAlgorithm = macAlgorithm;
  }

  @Override
  public String getSecretKey() {
    return secretKey;
  }

  @Override
  public void setSecretKey(String secretKey) {
    this.secretKey = secretKey;
  }

  @Override
  public String getCipherAlgorithm() {
    return cipherAlgorithm;
  }

  @Override
  public void setCipherAlgorithm(String cipherAlgorithm) {
    this.cipherAlgorithm = cipherAlgorithm;
  }

  @Override
  public String getPath() {
    return path;
  }

  @Override
  public void setPath(String path) {
    this.path = path;
  }

  @Override
  public String getDomain() {
    return this.domain;
  }

  @Override
  public void setDomain(String domain) {
    this.domain = domain;
  }

  @Override
  public int getMaxSessionCookieSize() {
    return maxSessionCookieSize;
  }

  @Override
  public void setMaxSessionCookieSize(int maxSessionCookieSize) {
    if (maxSessionCookieSize < 1024 || maxSessionCookieSize > 4096) {
      this.maxSessionCookieSize = 2048;
    } else {
      this.maxSessionCookieSize = maxSessionCookieSize;
    }
  }

  @Override
  public Duration getMaxInactivityInterval() {
    return maxInactivityInterval;
  }

  @Override
  public void setMaxInactivityInterval(Duration maxInactivityInterval) {
    this.maxInactivityInterval = maxInactivityInterval;
  }
}
