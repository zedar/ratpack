/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ratpack.session.clientside.internal;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import io.netty.handler.codec.base64.Base64;
import io.netty.handler.codec.base64.Base64Dialect;
import io.netty.handler.codec.http.Cookie;
import io.netty.util.CharsetUtil;
import ratpack.exec.ExecControl;
import ratpack.exec.Promise;
import ratpack.http.Request;
import ratpack.http.Response;
import ratpack.session.clientside.ClientSideSessionConfig;
import ratpack.session.clientside.Crypto;
import ratpack.session.clientside.Signer;
import ratpack.session.internal.SessionId;
import ratpack.session.store.SessionStoreAdapter;

import java.nio.CharBuffer;
import java.util.Set;

/**
 * The session store adapter for coookie based session.
 * <p>
 * It is execution scoped, so every executions gets its own instance with access to request and response.
 */
public class DefaultClientSideSessionStoreAdapter implements SessionStoreAdapter {

  private static final String SESSION_SEPARATOR = ":";

  private final ExecControl execControl;
  private final Request request;
  private final Response response;
  private final Signer signer;
  private final Crypto crypto;
  private final ClientSideSessionConfig config;

  /**
   * Create instance of cookie based (client side) session store adapter.
   *
   * @param execControl the execution control
   * @param request the request
   * @param response the response
   * @param signer the signer used to sign byte buffer with the secret key
   * @param crypto the symetric-key encryptor/decryptor
   * @param config the client side session configuration
   */
  public DefaultClientSideSessionStoreAdapter(ExecControl execControl, Request request, Response response, Signer signer, Crypto crypto, ClientSideSessionConfig config) {
    this.execControl = execControl;
    this.request = request;
    this.response = response;
    this.signer = signer;
    this.crypto = crypto;
    this.config = config;
  }

  /**
   * Store serialized session data as a set of {@link ratpack.http.Response} cookies.
   *
   * @param sessionId cookie based session does not have id
   * @param bufferAllocator the buffer allocator
   * @param sessionData the serialized session data
   * @return the promise for the result of saving the session data in cookies
   */
  @Override
  public Promise<Boolean> store(SessionId sessionId, ByteBufAllocator bufferAllocator, ByteBuf sessionData) {
    return execControl.promiseFrom(() -> {
      String[] sessionCookiePartitions = serialize(bufferAllocator, sessionData);
      for (int i = 0; i < sessionCookiePartitions.length; i++) {
        addSessionCookie(config.getSessionCookieName() + "_" + i, sessionCookiePartitions[i]);
      }
      for (int i = sessionCookiePartitions.length; i < getSessionCookies().length; i++) {
        invalidateSessionCookie(config.getSessionCookieName() + "_" + i);
      }
    });
  }

  /**
   * Load session data (still serialized) from {@link ratpack.http.Request}, verify if they were not tempered and then decrypt.
   *
   * @param sessionId cookie based session does not have id
   * @param bufferAllocator the buffer allocator
   * @return the promise for byte buffer with serialized session data
   */
  @Override
  public Promise<ByteBuf> load(SessionId sessionId, ByteBufAllocator bufferAllocator) {
    return null;
  }

  /**
   * Remove session data from cookies stored in {@link ratpack.http.Response}.
   *
   * @param sessionId cookie based session does not have id
   * @return the promise for the result of session termination
   */
  @Override
  public Promise<Boolean> remove(SessionId sessionId) {
    return null;
  }

  /**
   * If cookie based session is provided, return 1, else 0.
   *
   * @return 1 if cookies contain session data, 0 elsewhere
   */
  @Override
  public long size() {
    return -1;
  }

  private String[] serialize(ByteBufAllocator bufferAllocator, ByteBuf sessionData) {
    ByteBuf encrypted = crypto.encrypt(sessionData, bufferAllocator);
    String encryptedBase64 = toBase64(encrypted);
    ByteBuf digest = signer.sign(encrypted.resetReaderIndex(), bufferAllocator);
    String digestBase64 = toBase64(digest);

    digest.release();
    encrypted.release();

    String digestedBase64 = encryptedBase64 + SESSION_SEPARATOR + digestBase64;
    if (digestedBase64.length() <= config.getMaxSessionCookieSize()) {
      return new String[]{digestedBase64};
    }
    int count = (int) Math.ceil((double) digestedBase64.length() / config.getMaxSessionCookieSize());
    String[] partitions = new String[count];
    for (int i = 0; i < count; i++) {
      int from = i * config.getMaxSessionCookieSize();
      int to = Math.min(from + config.getMaxSessionCookieSize(), digestedBase64.length());
      partitions[i] = digestedBase64.substring(from, to);
    }
    return partitions;
  }

  private String toBase64(ByteBuf byteBuf) {
    ByteBuf encoded = Base64.encode(byteBuf, false, Base64Dialect.STANDARD);
    try {
      return encoded.toString(CharsetUtil.ISO_8859_1);
    } finally {
      encoded.release();
    }
  }

  private ByteBuf fromBase64(ByteBufAllocator bufferAllocator, String string) {
    ByteBuf byteBuf = ByteBufUtil.encodeString(bufferAllocator, CharBuffer.wrap(string), CharsetUtil.ISO_8859_1);
    try {
      return Base64.decode(byteBuf, Base64Dialect.STANDARD);
    } finally {
      byteBuf.release();
    }
  }

  private Cookie[] getSessionCookies() {
    Set<Cookie> cookies = request.getCookies();
    if (cookies == null) {
      return new Cookie[0];
    }
    return cookies
      .stream()
      .filter(c -> c.name().startsWith(config.getSessionCookieName()))
      .sorted((c1, c2) -> c1.name().compareTo(c2.name()))
      .toArray(Cookie[]::new);
  }

  private void invalidateSessionCookie(String cookieName) {
    Cookie cookie = response.expireCookie(cookieName);
    if (config.getPath() != null) {
      cookie.setPath(config.getPath());
    }
    if (config.getDomain() != null) {
      cookie.setDomain(config.getDomain());
    }
  }

  private void addSessionCookie(String name, String value) {
    Cookie sessionCookie = response.cookie(name, value);
    if (config.getPath() != null) {
      sessionCookie.setPath(config.getPath());
    }
    if (config.getDomain() != null) {
      sessionCookie.setDomain(config.getDomain());
    }
  }

}
