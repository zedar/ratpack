package ratpack.session.clientside;

import ratpack.guice.ConfigurableModule;
import ratpack.guice.ExecutionScoped;
import ratpack.server.ServerConfig;
import ratpack.session.clientside.internal.DefaultClientSideSessionConfig;
import ratpack.session.internal.SessionStatus;
import ratpack.session.internal.StoreSessionIfDirtyHandlerDecorator;

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


}
