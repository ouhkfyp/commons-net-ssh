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
package org.apache.commons.net.ssh.random;

import org.apache.commons.net.ssh.Factory;

/**
 * A random factory wrapper that uses a single random instance. The underlying random instance has to be thread safe.
 */
public class SingletonRandomFactory implements Random, Factory<Random>
{
    private final Random random;
    
    public SingletonRandomFactory(Factory<Random> factory)
    {
        random = factory.create();
    }
    
    public Random create()
    {
        return this;
    }
    
    public void fill(byte[] bytes, int start, int len)
    {
        random.fill(bytes, start, len);
    }
    
}
