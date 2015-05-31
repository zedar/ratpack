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

package ratpack.session.clientside

import com.google.common.collect.Maps
import io.netty.handler.codec.http.Cookie
import ratpack.registry.Registry
import ratpack.session.SessionAdapter
import ratpack.session.store.SessionStorage
import ratpack.test.internal.RatpackGroovyDslSpec
import spock.lang.Ignore

import java.time.Duration
import java.util.concurrent.atomic.AtomicInteger
import java.util.stream.Collectors

class ClientSideSessionCookiesSpec extends RatpackGroovyDslSpec {
  private static final String LAST_ACCESS_TIME_TOKEN = "\$LAT\$"

  private static class SessionServiceWrapper {
    private final Registry registry
    private final SessionService sessionService

    SessionServiceWrapper(final Registry registry) {
      this.registry = registry
      this.sessionService = registry.get(SessionService)
    }

    def deserializeSession(Cookie[] cookies) {
      return sessionService.deserializeSession(registry, cookies)
    }
  }

  private String[] getSessionCookies(String path) {
    List<Cookie> pathCookies = getCookies(path)
    if (pathCookies == null) {
      return []
    }
    pathCookies.stream().findAll { it.name.startsWith("ratpack_session")?.value }.toArray()
  }

  private def getSessionAttrs(SessionServiceWrapper sessionService, String path) {
    List<Cookie> cookies = getCookies(path)
    def attrs = [:]
    cookies = cookies
      .stream()
      .filter{ c ->
        c.name().startsWith("ratpack_session") == true
      }
      .collect(Collectors.toList())
    if (cookies) {
      def m = sessionService.deserializeSession((Cookie[])cookies.toArray())
      if (m) {
        attrs.putAll(m)
      }
    }
    attrs.remove(LAST_ACCESS_TIME_TOKEN)

    return attrs
  }

  private long getSessionLastAccessTime(SessionServiceWrapper sessionService, String path) {
    List<Cookie> cookies = getCookies(path)
    cookies = cookies
      .stream()
      .filter { c -> c.name().startsWith("ratpack_session") == true }
      .collect()
    String time = "-1"
    if (cookies) {
      def m = sessionService.deserializeSession((Cookie[])cookies.toArray())
      if (m) {
        time = (String)m.getOrDefault(LAST_ACCESS_TIME_TOKEN, "-1")
      }
    }
    return Long.valueOf(time)
  }

  def "cookies assigned to path are send for this path only"() {
    given:
    bindings {
      module NewClientSideSessionModule, {
        it.with {
          path = "/bar"
        }
      }
    }

    handlers {
      get("foo") { SessionAdapter session ->
        session.get("value").then {
          render it.orElse("null")
        }
      }
      get("bar") { SessionAdapter session ->
        session.get("value").then {
          render it.orElse("null")
        }
      }
      get("") { SessionAdapter session ->
        session.get("value").then {
          render it.orElse("null")
        }
      }
      get("val/:value") { SessionAdapter session ->
        session.set("value", pathTokens.value).then {
          session.get("value").then {
            render it.orElse("null")
          }
        }
      }
    }

    when:
    get("foo")
    String[] setCookiesRoot = getSessionCookies("/")
    String[] setCookiesBar = getSessionCookies("/bar")
    String[] setCookiesVal = getSessionCookies("/val")

    then:
    setCookiesRoot.length == 0
    setCookiesBar.length == 0
    setCookiesVal.length == 0

    when:
    get("val/foo")
    setCookiesRoot = getSessionCookies("/")
    setCookiesBar = getSessionCookies("/bar")
    setCookiesVal = getSessionCookies("/val")

    then:
    setCookiesRoot.length == 0
    setCookiesBar.length == 1
    setCookiesVal.length == 0
  }

  def "cookie is send in request for the given path only"() {
    given:
    bindings {
      module NewClientSideSessionModule, {
        it.with {
          path = "/foo"
        }
      }
    }
    handlers {
      get("/foo/:value") { SessionAdapter session ->
        if (pathTokens.value == "check") {
          session.get("value").then {
            render it.orElse("null")
          }
        } else {
          session.set("value", pathTokens.value).then {
            session.get("value").then {
              render it.orElse("null")
            }
          }
        }
      }
      get("/bar") { SessionAdapter session ->
        session.get("value").then {
          render it.orElse("null")
        }
      }
    }

    when:
    get("/foo/val1")
    get("/bar")

    then:
    response.body.text == "null"

    when:
    get("/foo/check")

    then:
    response.body.text == "val1"
  }

  def "removed session attribute is no longer accessible"() {
    given:
    bindings {
      module ClientSideSessionsModule, {
        it.with {
          secretKey = "aaaaaaaaaaaaaaaa"
        }
      }
    }
    def clientSessionService = null
    handlers {
      if (!clientSessionService) {
        clientSessionService = new SessionServiceWrapper(registry)
      }
      get("foo/:value") { SessionStorage sessionStorage ->
        sessionStorage.set("foo", pathTokens.value).then({
          sessionStorage.get("foo", String).then({
            render it.orElse("null")
          })
        })
      }
      get("clear") { SessionStorage sessionStorage ->
        sessionStorage.remove("foo").then({
          render "null"
        })
      }
    }

    when:
    get("foo/val1")
    String[] setCookies = getSessionCookies("/")
    clientSessionService
    def attrs = getSessionAttrs(clientSessionService, "/")

    then:
    setCookies.length == 1
    attrs.size() == 1
    attrs.foo == "val1"

    when:
    get("clear")
    setCookies = getSessionCookies("/")
    attrs = getSessionAttrs(clientSessionService, "/")

    then:
    setCookies.length == 0
    attrs.size() == 0
  }

  public static class SessionKeys {
    Map<String, String> strings = Maps.newHashMap()
    Map<Class<?>, Object> objects = Maps.newHashMap()
  }

  def "removed session attribute does not clear the other attributes"() {
    bindings {
      module NewClientSideSessionModule, {
        it.with {
          secretKey = "aaaaaaaaaaaaaaaa"
        }
      }
      bindInstance(SessionKeys, new SessionKeys())
    }
    Registry reg
    handlers {
      if (!reg) {
        reg = registry
      }
      get("s/:attr/:value") { SessionAdapter session ->
        String attr = pathTokens.attr
        String value = pathTokens.value
        if (attr && value) {
          session.set(attr, value).then {
            session.get(attr).then {
              render "ATTR: ${attr} VALUE: ${it.get()}"
            }
          }
        } else {
          clientError(404)
        }
      }
      get("sessionvalues") { SessionAdapter session, SessionKeys sessionKeys ->
        session.getStringKeys().then { keys ->
          sessionKeys.strings.clear()
          AtomicInteger count = new AtomicInteger(keys.size())
          keys.forEach { key ->
            session.get(key).then { value ->
              sessionKeys.strings[key] = value.orElse("null")
              if (count.decrementAndGet() == 0) {
                render ""
              }
            }

          }
        }
      }
      get("clear/:attr") { SessionAdapter session ->
        String attr = pathTokens.attr
        if (attr) {
          session.remove(attr).then({
            session.get(attr).onError {th ->
              render "null"
            }.then {
              render it.orElse("null")
            }
          })
        } else {
          clientError(404)
        }
      }
    }

    when:
    get("s/foo/bar")
    get("s/baz/quux")
    String[] setCookies = getSessionCookies("/")
    get("sessionvalues")

    then:
    SessionKeys sessionKeys = reg.get(SessionKeys)
    sessionKeys
    setCookies.length == 1

    sessionKeys.strings.size() == 2
    sessionKeys.strings["foo"] == "bar"
    sessionKeys.strings["baz"] == "quux"

    when:
    get("clear/foo")
    setCookies = getSessionCookies("/")
    get("sessionvalues")

    then:
    setCookies.length == 1
    sessionKeys.strings.size() == 1
    !sessionKeys.strings["foo"]
    sessionKeys.strings["baz"] == "quux"
  }

  def "large session partitioned into many session cookies - values serialized as string"() {
    bindings {
      module NewClientSideSessionModule, {
        it.with {
          secretKey = "aaaaaaaaaaaaaaaa"
        }
      }
      bindInstance(SessionKeys, new SessionKeys())
    }

    Registry reg
    handlers {
      if (!reg) {
        reg = registry
      }
      get("set") { SessionAdapter session ->
        String value = ""
        for (int i = 0; i < 800/*1024*/; i++) {
          value += "ab"
        }
        session.set("foo", value).then {
          session.get("foo").then {
            render "SET"
          }
        }
      }
      get("setsmall") { SessionAdapter session ->
        session.set("foo", "val1").then {
          session.get("foo").then {
            render it.orElse("null")
          }
        }
      }
      get("clear") { SessionAdapter session ->
        session.remove("foo").then {
          render ""
        }
      }
      get("sessionvalues") { SessionAdapter session, SessionKeys sessionKeys ->
        session.getStringKeys().then { keys ->
          sessionKeys.strings.clear()
          AtomicInteger count = new AtomicInteger(keys.size())
          keys.forEach { key ->
            session.get(key).then { value ->
              sessionKeys.strings[key] = value.orElse("null")
              if (count.decrementAndGet() == 0) {
                render "FINISHED TEST"
              }
            }

          }
        }
      }
    }

    when:
    get("set")

    then:
    getCookies("/").size() == 2

    when:
    get("setsmall")

    then:
    getCookies("/").size() == 1

    when:
    get("clear")

    then:
    getCookies("/").size() == 1
    SessionKeys sessionKeys = reg.get(SessionKeys)
    sessionKeys
    sessionKeys.strings.size() == 0

    when:
    get("set")

    then:
    getCookies("/").size() == 2

    when:
    get("clear")
    get("sessionvalues")

    then:
    getCookies("/").size() == 1
    sessionKeys.strings.size() == 0
  }

  @Ignore
  def "session last access time is defined"() {
    bindings {
      module ClientSideSessionsModule, {
        it.with {
          secretKey = "aaaaaaaaaaaaaaaa"
        }
      }
    }

    def clientSessionService = null
    handlers {
      if (!clientSessionService) {
        clientSessionService = new SessionServiceWrapper(registry)
      }
      get("s/:attr/:value") { SessionStorage sessionStorage ->
        String attr = pathTokens.attr
        String value = pathTokens.value
        if (attr && value) {
          sessionStorage.set(attr, value).then {
            sessionStorage.get(attr, Object).then {
              render "ATTR: ${attr} VALUE: ${it.get()}"
            }
          }
        } else {
          clientError(404)
        }
      }
    }

    when:
    get("s/foo/bar")
    long lastAccessTime = getSessionLastAccessTime(clientSessionService, "/")

    then:
    lastAccessTime > 0
  }

  @Ignore
  def "timed out session returns changed attribute"() {
    bindings {
      module ClientSideSessionsModule, {
        it.with {
          secretKey = "aaaaaaaaaaaaaaaa"
          maxInactivityInterval = Duration.ofSeconds(1)
        }
      }
    }

    def clientSessionService = null
    handlers {
      if (!clientSessionService) {
        clientSessionService = new SessionServiceWrapper(registry)
      }
      get("wait") { SessionStorage sessionStorage ->
        Thread.sleep(1100)
        render "null"
      }
      get("") { SessionStorage sessionStorage ->
        sessionStorage.get("foo", String).then {
          sessionStorage.set("foo", it.orElse("buzz")).then {
            render it?.toString()
          }
        }
      }
      get("s/:attr/:value") { SessionStorage sessionStorage ->
        String attr = pathTokens.attr
        String value = pathTokens.value
        if (attr && value) {
          sessionStorage.set(attr, value).then {
            sessionStorage.get(attr, Object).then {
              render "ATTR: ${attr} VALUE: ${it.get()}"
            }
          }
        } else {
          clientError(404)
        }
      }
    }

    when:
    get("s/foo/bar")
    def attrs = getSessionAttrs(clientSessionService, "/")
    long lastAccessTime = getSessionLastAccessTime(clientSessionService, "/")

    then:
    attrs["foo"] == "bar"
    lastAccessTime > 0

    when:
    get("wait")
    get("")
    attrs = getSessionAttrs(clientSessionService, "/")
    lastAccessTime = getSessionLastAccessTime(clientSessionService, "/")

    then:
    attrs["foo"] == "buzz"
    lastAccessTime > -1
  }

  @Ignore
  def "timed out session does not return expired attributes"() {
    bindings {
      module ClientSideSessionsModule, {
        it.with {
          secretKey = "aaaaaaaaaaaaaaaa"
          maxInactivityInterval = Duration.ofSeconds(1)
        }
      }
    }

    def clientSessionService = null
    handlers {
      if (!clientSessionService) {
        clientSessionService = new SessionServiceWrapper(registry)
      }
      get("wait") { SessionStorage sessionStorage ->
        Thread.sleep(1100)
        render "null"
      }
      get("") { SessionStorage sessionStorage ->
        render "null"
      }
      get("s/:attr/:value") { SessionStorage sessionStorage ->
        String attr = pathTokens.attr
        String value = pathTokens.value
        if (attr && value) {
          sessionStorage.set(attr, value).then {
            sessionStorage.get(attr, String).then {
              render "ATTR: ${attr} VALUE: ${it.orElse('null')}"
            }
          }
        } else {
          clientError(404)
        }
      }
    }

    when:
    get("s/foo/bar")
    def attrs = getSessionAttrs(clientSessionService, "/")
    long lastAccessTime = getSessionLastAccessTime(clientSessionService, "/")

    then:
    attrs["foo"] == "bar"
    lastAccessTime > 0

    when:
    get("wait")
    get("")
    attrs = getSessionAttrs(clientSessionService, "/")
    lastAccessTime = getSessionLastAccessTime(clientSessionService, "/")

    then:
    attrs["foo"] == null
    lastAccessTime == -1
  }

  public static class FooSessionAttribute implements Serializable {
    String value
  }

  def "serialization of Integer returns Integer"() {
    bindings {
      module NewClientSideSessionModule, {
        it.with {
          secretKey = "aaaaaaaaaaaaaaaa"
        }
      }
      bindInstance(SessionKeys, new SessionKeys())
    }

    Registry reg
    handlers {
      if (!reg) {
        reg = registry
      }
      get("") { SessionAdapter session ->
        render "null"
      }
      get("s/:attr") { SessionAdapter session ->
        String attr = pathTokens.attr
        if (attr) {
          session.set(Integer.valueOf(10)).then {
            render ""
          }
        } else {
          clientError(404)
        }
      }
      get("sessionvalues") { SessionAdapter session, SessionKeys sessionKeys ->
        session.getTypeKeys().then { keys ->
          sessionKeys.objects.clear()
          AtomicInteger count = new AtomicInteger(keys.size())
          keys.forEach { type ->
            session.get(type).then { value ->
              sessionKeys.objects[type] = value.orElse(null)
              if (count.decrementAndGet() == 0) {
                render ""
              }
            }
          }
        }
      }
    }

    when:
    get("s/foo")
    get("sessionvalues")

    then:
    SessionKeys sessionKeys = reg.get(SessionKeys)
    sessionKeys
    sessionKeys.objects.size() == 1
    sessionKeys.objects[Integer]
    sessionKeys.objects[Integer] instanceof Integer
    sessionKeys.objects[Integer] == 10
  }

  def "serialization of custom class returns its instance"() {
    bindings {
      module NewClientSideSessionModule, {
        it.with {
          secretKey = "aaaaaaaaaaaaaaaa"
        }
      }
      bindInstance(SessionKeys, new SessionKeys())
    }

    Registry reg
    handlers {
      if (!reg) {
        reg = registry
      }
      get("") { SessionAdapter session ->
        render "null"
      }
      get("s/foo") { SessionAdapter session ->
        SerializableTypes.TypeA t = new SerializableTypes.TypeA()
        t.valueInt = Integer.valueOf(10)
        t.valueDouble = Double.valueOf(10.123)
        session.set(t).then {
          render "ATTR: foo"
        }
      }
      get("s/bar") { SessionAdapter session ->
        SerializableTypes.TypeA ta = new SerializableTypes.TypeA()
        ta.valueInt = Integer.valueOf(20)
        ta.valueDouble = Double.valueOf(20.123)
        SerializableTypes.TypeB tb = new SerializableTypes.TypeB()
        tb.valueStr = "BAR"
        tb.typeA = ta
        session.set(tb).then {
          render "ATTR: bar"
        }
      }
      get("sessionvalues") { SessionAdapter session, SessionKeys sessionKeys ->
        session.getTypeKeys().then { keys ->
          sessionKeys.objects.clear()
          AtomicInteger count = new AtomicInteger(keys.size())
          keys.forEach { type ->
            session.get(type).then { value ->
              sessionKeys.objects[type] = value.orElse(null)
              if (count.decrementAndGet() == 0) {
                render ""
              }
            }
          }
        }
      }
    }

    when:
    get("s/foo")
    get("s/bar")
    get("sessionvalues")
    SessionKeys sessionKeys = reg.get(SessionKeys)

    then:
    sessionKeys
    sessionKeys.objects.size() == 2
    sessionKeys.objects[SerializableTypes.TypeA] instanceof SerializableTypes.TypeA
    with(sessionKeys.objects[SerializableTypes.TypeA]) {
      valueInt instanceof Integer
      valueDouble instanceof Double

      valueInt == Integer.valueOf(10)
      valueDouble == Double.valueOf(10.123)
    }
    sessionKeys.objects[SerializableTypes.TypeB] instanceof SerializableTypes.TypeB
    with (sessionKeys.objects[SerializableTypes.TypeB]) {
      valueStr == "BAR"
      typeA instanceof SerializableTypes.TypeA
      typeA.valueInt == 20
      typeA.valueDouble == 20.123
    }
  }
}
