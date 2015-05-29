package ratpack.session.clientside;

import java.time.Duration;

/**
 * Configuration of client side session module.
 */
public interface ClientSideSessionConfig {
  String getSessionCookieName();
  void setSessionCookieName(String sessionCookieName);
  String getSecretToken();
  void setSecretToken(String secretToken);
  String getMacAlgorithm();
  void setMacAlgorithm(String macAlgorithm);
  String getSecretKey();
  void setSecretKey(String secretKey);
  String getCipherAlgorithm();
  void setCipherAlgorithm(String cipherAlgorithm);
  String getPath();
  void setPath(String path);
  String getDomain();
  void setDomain(String domain);
  int getMaxSessionCookieSize();
  void setMaxSessionCookieSize(int maxSessionCookieSize);
  Duration getMaxInactivityInterval();
  void setMaxInactivityInterval(Duration maxInactivityInterval);
}
