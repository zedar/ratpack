package ratpack.session.clientside.internal;

import ratpack.session.internal.SessionId;

/**
 * An extension of {@link ratpack.session.internal.SessionId} that omits reading of {@code SESSION_ID} attribute.
 * <p>
 * Client side session is stored in own <b>cookies</b>.
 */
public class DefaultClientSideSessionId implements SessionId {
  @Override
  public String getValue() {
    return null;
  }

  @Override
  public void terminate() {
  }
}
