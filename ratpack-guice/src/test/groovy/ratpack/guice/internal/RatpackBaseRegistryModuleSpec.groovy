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

package ratpack.guice.internal

import com.google.inject.Injector
import com.google.inject.Key
import com.google.inject.TypeLiteral
import io.netty.buffer.ByteBufAllocator
import org.reactivestreams.Publisher
import ratpack.error.ClientErrorHandler
import ratpack.error.ServerErrorHandler
import ratpack.exec.ExecControl
import ratpack.exec.ExecController
import ratpack.exec.Execution
import ratpack.exec.SuccessPromise
import ratpack.exec.internal.DefaultExecController
import ratpack.file.FileSystemBinding
import ratpack.file.MimeTypes
import ratpack.form.internal.FormParser
import ratpack.guice.Guice
import ratpack.handling.Redirector
import ratpack.http.client.HttpClient
import ratpack.render.Renderable
import ratpack.render.Renderer
import ratpack.server.PublicAddress
import ratpack.server.RatpackServer
import ratpack.server.ServerConfig
import ratpack.server.internal.ServerRegistry
import spock.lang.Specification
import spock.lang.Subject

import java.nio.file.Path

@Subject(RatpackBaseRegistryModule)
class RatpackBaseRegistryModuleSpec extends Specification {
  def "injector contains bindings based on base registry"() {
    when:
    def ratpackServer = Mock(RatpackServer)
    def execController = new DefaultExecController(4)
    def serverConfig = ServerConfig.noBaseDir().build()
    def baseRegistry = ServerRegistry.serverRegistry(ratpackServer, execController, serverConfig, Guice.registry {})
    def injector = baseRegistry.get(Injector)

    then:
    injector.getInstance(ServerConfig) == serverConfig
    injector.getInstance(ByteBufAllocator) == baseRegistry.get(ByteBufAllocator)
    injector.getInstance(ExecController) == baseRegistry.get(ExecController)
    injector.getInstance(MimeTypes) == baseRegistry.get(MimeTypes)
    injector.getInstance(PublicAddress) == baseRegistry.get(PublicAddress)
    injector.getInstance(Redirector) == baseRegistry.get(Redirector)
    injector.getInstance(ClientErrorHandler) == baseRegistry.get(ClientErrorHandler)
    injector.getInstance(ServerErrorHandler) == baseRegistry.get(ServerErrorHandler)
    injector.getInstance(RatpackServer) == ratpackServer
    injector.getInstance(Key.get(new TypeLiteral<Renderer<Path>>() {}))
    injector.getInstance(Key.get(new TypeLiteral<Renderer<SuccessPromise>>() {}))
    injector.getInstance(Key.get(new TypeLiteral<Renderer<Publisher>>() {}))
    injector.getInstance(Key.get(new TypeLiteral<Renderer<Renderable>>() {}))
    injector.getInstance(Key.get(new TypeLiteral<Renderer<CharSequence>>() {}))
    injector.getInstance(Key.get(new TypeLiteral<Set<FormParser>>() {})).collect { it.contentType }.sort() == ["application/x-www-form-urlencoded", "multipart/form-data"]
    !injector.getExistingBinding(Key.get(FileSystemBinding))
    injector.getInstance(ExecControl) == baseRegistry.get(ExecController).control
    injector.getExistingBinding(Key.get(Execution))
    injector.getInstance(HttpClient)
  }
}
