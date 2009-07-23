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

import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.AbstractService;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;
import org.apache.commons.net.ssh.util.Future;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Constants.Message;

/**
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class ConnectionProtocol extends AbstractService implements ConnectionService
{
    
    protected int windowSize = 0x200000;
    protected int maxPacketSize = 0x8800;
    protected int timeout = 15;
    
    protected final Map<Integer, Channel> channels = new ConcurrentHashMap<Integer, Channel>();
    protected Map<String, OpenReqHandler> orh = new ConcurrentHashMap<String, OpenReqHandler>();
    
    private final AtomicInteger nextID = new AtomicInteger();
    
    protected final Lock lock = new ReentrantLock();
    protected Queue<Future<Buffer, ConnectionException>> globalReqs =
            new LinkedList<Future<Buffer, ConnectionException>>();
    
    public ConnectionProtocol(Transport session)
    {
        super(session);
    }
    
    public void attach(Channel chan)
    {
        channels.put(chan.getID(), chan);
    }
    
    public void attach(OpenReqHandler handler)
    {
        orh.put(handler.getSupportedChannelType(), handler);
    }
    
    public void forget(Channel chan)
    {
        channels.remove(chan.getID());
    }
    
    public void forget(OpenReqHandler handler)
    {
        orh.remove(handler.getSupportedChannelType());
    }
    
    public Channel get(int id)
    {
        return channels.get(id);
    }
    
    public OpenReqHandler get(String chanType)
    {
        return orh.get(chanType);
    }
    
    public int getMaxPacketSize()
    {
        return maxPacketSize;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    public int getTimeout()
    {
        return timeout;
    }
    
    @Override
    public Transport getTransport()
    {
        return trans;
    }
    
    public int getWindowSize()
    {
        return windowSize;
    }
    
    public void handle(Message cmd, Buffer buf) throws ConnectionException, TransportException
    {
        int num = cmd.toInt();
        
        if (num < 80 || num > 100)
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR);
        
        else if (num <= 90)
            switch (cmd)
            {
                case REQUEST_SUCCESS:
                    gotResponse(buf);
                    break;
                case REQUEST_FAILURE:
                    gotResponse(null);
                    break;
                case CHANNEL_OPEN:
                    String type = buf.getString();
                    log.debug("Received CHANNEL_OPEN for `{}` channel", type);
                    if (orh.containsKey(type))
                        orh.get(type).handleOpenReq(buf);
                    else
                        log.warn("No handler found for `{}` CHANNEL_OPEN request", type);
                    break;
                default:
                    trans.sendUnimplemented();
            }
        else
            getChannel(buf).handle(cmd, buf);
    }
    
    public int nextID()
    {
        return nextID.getAndIncrement();
    }
    
    public synchronized void notifyError(SSHException ex)
    {
        Future.Util.<Buffer, ConnectionException> notifyError(ex, globalReqs);
        for (Channel chan : channels.values()) {
            log.debug("Notifying channel #{}", chan.getID());
            chan.notifyError(ex);
        }
        channels.clear();
    }
    
    public void notifyUnimplemented(int seqNum) throws ConnectionException
    {
        throw new ConnectionException("Unexpected SSH_MSG_UNIMPLEMENTED");
    }
    
    public synchronized Future<Buffer, ConnectionException> sendGlobalRequest(String name, boolean wantReply,
            Buffer specifics) throws TransportException
    {
        log.info("Sending GLOBAL_REQUEST for {}, wantReply={}", name, wantReply);
        trans.writePacket(new Buffer(Message.GLOBAL_REQUEST) //
                                                            .putString(name) //
                                                            .putBoolean(wantReply) //
                                                            .putBuffer(specifics)); //
        
        Future<Buffer, ConnectionException> future = null;
        if (wantReply) {
            future =
                    new Future<Buffer, ConnectionException>("global req for " + name, ConnectionException.chainer, null);
            globalReqs.add(future);
        }
        return future;
    }
    
    public void setMaxPacketSize(int maxPacketSize)
    {
        this.maxPacketSize = maxPacketSize;
    }
    
    public void setTimeout(int timeout)
    {
        this.timeout = timeout;
    }
    
    public void setWindowSize(int windowSize)
    {
        this.windowSize = windowSize;
    }
    
    protected Channel getChannel(Buffer buffer) throws ConnectionException
    {
        int recipient = buffer.getInt();
        Channel channel = channels.get(recipient);
        if (channel == null) {
            buffer.rpos(buffer.rpos() - 5);
            Constants.Message cmd = buffer.getCommand();
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR, "Received " + cmd + " on unknown channel #"
                    + recipient);
        }
        return channel;
    }
    
    protected synchronized void gotResponse(Buffer response) throws ConnectionException
    {
        Future<Buffer, ConnectionException> gr = globalReqs.poll();
        if (gr != null) {
            if (response != null)
                gr.set(response);
            else
                gr.error("Global request failed");
        } else
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR);
    }
    
}
