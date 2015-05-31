/*
 * Copyright 2014 the original author or authors.
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
