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

package ratpack.session.internal;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import io.netty.buffer.*;
import ratpack.exec.Promise;
import ratpack.session.SessionAdapter;
import ratpack.session.SessionValueSerializer;
import ratpack.session.SyncSession;
import ratpack.session.store.SessionStoreAdapter;
import ratpack.util.Exceptions;
import ratpack.util.Types;

import java.io.*;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import static ratpack.exec.ExecControl.execControl;

public class DefaultSessionAdapter implements SessionAdapter {

  private final Map<String, String> strings = Maps.newHashMap();
  private final Map<Class<?>, byte[]> objects = Maps.newHashMap();

  private final SessionId sessionId;
  private final ByteBufAllocator bufferAllocator;
  private final SessionStoreAdapter storeAdapter;
  private final SessionStatus sessionStatus;
  private final SessionValueSerializer defaultSerializer;

  boolean needsLoad = true;
  private final SyncSession sync = new Sync();

  private static class Data implements Serializable {
    Map<String, String> strings;
    Map<Class<?>, byte[]> objects;

    public Data(Map<String, String> strings, Map<Class<?>, byte[]> objects) {
      this.strings = strings;
      this.objects = objects;
    }
  }

  public DefaultSessionAdapter(SessionId sessionId, ByteBufAllocator bufferAllocator, SessionStoreAdapter storeAdapter, SessionStatus sessionStatus, SessionValueSerializer defaultSerializer) {
    this.sessionId = sessionId;
    this.bufferAllocator = bufferAllocator;
    this.storeAdapter = storeAdapter;
    this.sessionStatus = sessionStatus;
    this.defaultSerializer = defaultSerializer;
  }

  @Override
  public Promise<SyncSession> getSync() {
    if (needsLoad) {
      return storeAdapter.load(sessionId, bufferAllocator).map(data -> {
        needsLoad = false;
        try {
          hydrate(data);
        } finally {
          data.release();
        }
        return sync;
      });
    } else {
      return execControl().promiseOf(sync);
    }
  }

  private void hydrate(ByteBuf data) {
    if (data.readableBytes() > 0) {
      try {
        Data deserializedData = defaultSerializer.deserialize(Data.class, new ByteBufInputStream(data));
        this.strings.clear();
        this.strings.putAll(deserializedData.strings);
        this.objects.clear();
        this.objects.putAll(deserializedData.objects);
        sessionStatus.setDirty(false);
      } catch (Exception e) {
        throw Exceptions.uncheck(e);
      }
    }
  }


  @Override
  public boolean isDirty() {
    return sessionStatus.isDirty();
  }

  private ByteBuf serialize() {
    Data data = new Data(strings.isEmpty() ? Maps.newHashMap() : ImmutableMap.copyOf(strings), ImmutableMap.copyOf(objects));
    ByteBuf buffer = bufferAllocator.buffer();
    OutputStream outputStream = new ByteBufOutputStream(buffer);
    try {
      defaultSerializer.serialize(Data.class, data, outputStream);
      outputStream.close();
      return buffer;
    } catch (Throwable e) {
      buffer.release();
      throw Exceptions.uncheck(e);
    }
  }

  @Override
  public Promise<Boolean> save() {
    return storeAdapter.store(sessionId, bufferAllocator, serialize()).map(value -> {
      sessionStatus.setDirty(false);
      return value;
    });
  }

  @Override
  public Promise<Boolean> terminate() {
    return storeAdapter.remove(sessionId).map(result -> {
      sessionId.terminate();
      hydrate(Unpooled.buffer(0, 0));
      return result;
    });
  }

  private void markDirty() {
    sessionStatus.setDirty(true);
  }

  private class Sync implements SyncSession {

    @Override
    public Optional<String> get(String key) {
      return Optional.ofNullable(strings.get(key));
    }

    @Override
    public <T> Optional<? extends T> get(Class<T> key) {
      return get(key, defaultSerializer);
    }

    @Override
    public <T> Optional<? extends T> get(Class<T> key, SessionValueSerializer serializer) {
      byte[] bytes = objects.get(key);
      if (bytes == null) {
        return Optional.empty();
      } else {
        try {
          return Optional.of(serializer.deserialize(key, new ByteArrayInputStream(bytes)));
        } catch (IOException e) {
          throw Exceptions.uncheck(e);
        }
      }
    }

    @Override
    public boolean set(String key, String value) {
      String prev = strings.put(key, value);
      if (prev == null || prev != null && !prev.equals(value)) {
        markDirty();
      }
      return prev != null;
    }

    @Override
    public <T> boolean set(Class<T> key, T value) {
      return set(key, value, defaultSerializer);
    }

    @Override
    public <T> boolean set(Class<T> key, T value, SessionValueSerializer serializer) {
      Objects.requireNonNull(key, "session key cannot be null");
      Objects.requireNonNull(value, "session value for key " + key.getName() + " cannot be null");

      ByteArrayOutputStream out = new ByteArrayOutputStream();
      try {
        serializer.serialize(key, value, out);
      } catch (IOException e) {
        throw Exceptions.uncheck(e);
      }

      markDirty();
      return objects.put(key, out.toByteArray()) != null;
    }

    @Override
    public <T> boolean set(T value) {
      return set(value, defaultSerializer);
    }

    @Override
    public <T> boolean set(T value, SessionValueSerializer serializer) {
      Class<T> type = Types.cast(value.getClass());
      return set(type, value, serializer);
    }

    @Override
    public Set<String> getStringKeys() {
      return strings.keySet();
    }

    @Override
    public Set<Class<?>> getTypeKeys() {
      return objects.keySet();
    }

    @Override
    public boolean remove(String key) {
      markDirty();
      return strings.remove(key) != null;
    }

    @Override
    public <T> boolean remove(Class<T> key) {
      markDirty();
      return objects.remove(key) != null;
    }

    @Override
    public boolean clear() {
      boolean change = !strings.isEmpty() || !objects.isEmpty();
      strings.clear();
      objects.clear();
      markDirty();
      return change;
    }

    @Override
    public boolean isDirty() {
      return DefaultSessionAdapter.this.isDirty();
    }

    @Override
    public Promise<Boolean> save() {
      return DefaultSessionAdapter.this.save();
    }

    @Override
    public Promise<Boolean> terminate() {
      return DefaultSessionAdapter.this.terminate();
    }
  }
}
