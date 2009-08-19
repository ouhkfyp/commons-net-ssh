/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.commons.net.ssh.util;

import java.util.concurrent.locks.ReentrantLock;

/*
 * Syntactic sugar around Future
 */

/**
 * A kind of {@link Future} that caters to boolean values.
 * <p>
 * An event can be set, cleared, or awaited, similar to Python's {@code threading.event}. The key
 * difference is that a waiter may be delivered an exception of parameterized type {@code T}.
 * Furthermore, an event {@link #isSet()} when it is not {@code null} i.e. it can be either {@code
 * true} or {@code false} when set.
 * 
 * @see Future
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class Event<T extends Throwable> extends Future<Boolean, T>
{
    
    /**
     * Creates this event with given {@code name} and exception {@code chainer}. Allocates a new
     * {@link java.util.concurrent.locks.Lock lock} object for this event.
     * 
     * @param name
     *            name of this event
     * @param chainer
     *            {@link FriendlyChainer} that will be used for chaining exceptions
     */
    public Event(String name, FriendlyChainer<T> chainer)
    {
        super(name, chainer);
    }
    
    /**
     * Creates this event with given {@code name}, exception {@code chainer}, and associated {@code
     * lock}.
     * 
     * @param name
     *            name of this event
     * @param chainer
     *            {@link FriendlyChainer} that will be used for chaining exceptions
     * @param lock
     *            lock to use
     */
    public Event(String name, FriendlyChainer<T> chainer, ReentrantLock lock)
    {
        super(name, chainer, lock);
    }
    
    /**
     * Await this event to have a definite {@code true} or {@code false} value.
     * 
     * @throws T
     *             if another thread meanwhile informs this event of an error
     */
    public void await() throws T
    {
        super.get();
    }
    
    /**
     * Await this event to have a definite {@code true} or {@code false} value, for {@code timeout}
     * seconds.
     * 
     * @param timeout
     *            timeout in seconds
     * @throws T
     *             if another thread meanwhile informs this event of an error, or timeout expires
     */
    public void await(int timeout) throws T
    {
        super.get(timeout);
    }
    
    /**
     * Sets this event to be {@code true}. Short for {@code set(true)}.
     */
    public void set()
    {
        super.set(true);
    }
    
}
