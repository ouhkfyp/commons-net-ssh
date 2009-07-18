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
package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A local/remote window for a given channel
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Window
{
    
    private final static Logger log = LoggerFactory.getLogger(Window.class);
    
    private final AbstractChannel channel;
    private final String name;
    
    private int size;
    private int maxSize;
    private int packetSize;
    private boolean waiting;
    
    public Window(AbstractChannel channel, boolean local)
    {
        this.channel = channel;
        this.name = (local ? "local " : "remote") + " window";
    }
    
    public synchronized void check(int maxFree) throws TransportException
    {
        int threshold = Math.min(packetSize * 8, maxSize / 4);
        if (maxFree - size > packetSize && (maxFree - size > threshold || size < threshold)) {
            if (log.isDebugEnabled())
                log.debug("Increase " + name + " by " + (maxFree - size) + " up to " + maxFree);
            channel.sendWindowAdjust(maxFree - size);
            size = maxFree;
        }
    }
    
    public synchronized void consume(int len)
    {
        //assert size > len;
        size -= len;
        if (log.isDebugEnabled())
            log.debug("Consume " + name + " by " + len + " down to " + size);
    }
    
    public synchronized void consumeAndCheck(int len) throws TransportException
    {
        consume(len);
        check(maxSize);
    }
    
    public synchronized void expand(int window)
    {
        size += window;
        if (log.isDebugEnabled())
            log.debug("Increase " + name + " by " + window + " up to " + size);
        notifyAll();
    }
    
    public int getMaxSize()
    {
        return maxSize;
    }
    
    public int getPacketSize()
    {
        return packetSize;
    }
    
    public int getSize()
    {
        return size;
    }
    
    public void init(int startSize, int maxPacketSize)
    {
        this.size = startSize;
        this.maxSize = startSize;
        this.packetSize = maxPacketSize;
    }
    
    public synchronized void waitAndConsume(int len) throws InterruptedException
    {
        while (size < len) {
            log.debug("Waiting for {} bytes on {}", len, name);
            waiting = true;
            wait();
        }
        if (waiting) {
            log.debug("Space available for {}", name);
            waiting = false;
        }
        consume(len);
    }
    
}
