package ratpack.session.clientside;

import com.google.inject.Provides;
import com.google.inject.Singleton;
import io.netty.buffer.ByteBufAllocator;
import io.netty.util.CharsetUtil;
import ratpack.exec.ExecControl;
import ratpack.guice.ConfigurableModule;
import ratpack.guice.ExecutionScoped;
import ratpack.http.Request;
import ratpack.http.Response;
import ratpack.server.ServerConfig;
import ratpack.session.JavaSerializationSessionValueSerializer;
import ratpack.session.SessionAdapter;
import ratpack.session.SessionValueSerializer;
import ratpack.session.clientside.internal.*;
import ratpack.session.internal.DefaultSessionAdapter;
import ratpack.session.internal.SessionId;
import ratpack.session.internal.SessionStatus;
import ratpack.session.internal.StoreSessionIfDirtyHandlerDecorator;
import ratpack.session.store.SessionStoreAdapter;

import javax.crypto.spec.SecretKeySpec;

/**
 * An extension module that provides a client side session store - cookie based.
 */
public class NewClientSideSessionModule extends ConfigurableModule<ClientSideSessionConfig> {
  @Override
  protected ClientSideSessionConfig createConfig(ServerConfig serverConfig) {
    return new DefaultClientSideSessionConfig();
  }

  @Override
  protected void configure() {
    bind(StoreSessionIfDirtyHandlerDecorator.class);
    bind(SessionStatus.class).in(ExecutionScoped.class);
  }

  @Provides
  @Singleton
  Signer signer(ClientSideSessionConfig config) {
    byte[] token = config.getSecretToken().getBytes(CharsetUtil.UTF_8);
    return new DefaultSigner(new SecretKeySpec(token, config.getMacAlgorithm()));
  }

  @Provides
  @Singleton
  Crypto crypto(ClientSideSessionConfig config) {
    if (config.getSecretKey() == null || config.getCipherAlgorithm() == null) {
      return NoCrypto.INSTANCE;
    } else {
      return new DefaultCrypto(config.getSecretKey().getBytes(CharsetUtil.UTF_8), config.getCipherAlgorithm());
    }
  }

  @Provides
  @Singleton
  SessionId sessionId() {
    return new DefaultClientSideSessionId();
  }

  @Provides
  @ExecutionScoped
  SessionStoreAdapter sessionStoreAdapter(ExecControl execControl, Request request, Response response, Signer signer, Crypto crypto, ClientSideSessionConfig config) {
    return new DefaultClientSideSessionStoreAdapter(execControl, request, response, signer, crypto, config);
  }

  @Provides
  SessionValueSerializer sessionValueSerializer() {
    return new JavaSerializationSessionValueSerializer();
  }

  @Provides
  @ExecutionScoped
  SessionAdapter sessionAdapter(SessionId sessionId, SessionStoreAdapter sessionStoreAdapter, SessionStatus sessionStatus, SessionValueSerializer sessionValueSerializer, ByteBufAllocator bufferAllocator) {
    return new DefaultSessionAdapter(sessionId, bufferAllocator, sessionStoreAdapter, sessionStatus, sessionValueSerializer);
  }
}
