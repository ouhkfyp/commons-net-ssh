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

import org.apache.commons.net.ssh.AbstractService;
import org.apache.commons.net.ssh.ErrorNotifiable;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.connection.OpenFailException.Reason;
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
public class ConnectionProtocol extends AbstractService implements Connection
{
    
    protected final AtomicInteger nextID = new AtomicInteger();
    
    protected final Map<Integer, Channel> channels = new ConcurrentHashMap<Integer, Channel>();
    
    protected final Map<String, ForwardedChannelOpener> openers =
            new ConcurrentHashMap<String, ForwardedChannelOpener>();
    
    protected final Queue<Future<Buffer, ConnectionException>> globalReqs =
            new LinkedList<Future<Buffer, ConnectionException>>();
    
    protected int windowSize = 2048 * 1024;
    protected int maxPacketSize = 32 * 1024;
    
    public ConnectionProtocol(Transport trans)
    {
        super("ssh-connection", trans);
    }
    
    public synchronized void attach(Channel chan)
    {
        log.info("Attaching `{}` channel (#{})", chan.getType(), chan.getID());
        channels.put(chan.getID(), chan);
    }
    
    public synchronized void attach(ForwardedChannelOpener opener)
    {
        log.info("Attaching opener for `{}` channels: {}", opener.getChannelType(), opener);
        openers.put(opener.getChannelType(), opener);
    }
    
    public synchronized void forget(Channel chan)
    {
        log.info("Forgetting `{}` channel (#{})", chan.getType(), chan.getID());
        channels.remove(chan.getID());
        notifyAll();
    }
    
    public synchronized void forget(ForwardedChannelOpener opener)
    {
        log.info("Forgetting opener for `{}` channels: {}", opener.getChannelType(), opener);
        openers.remove(opener.getChannelType());
    }
    
    public Channel get(int id)
    {
        return channels.get(id);
    }
    
    public synchronized ForwardedChannelOpener get(String chanType)
    {
        return openers.get(chanType);
    }
    
    public int getMaxPacketSize()
    {
        return maxPacketSize;
    }
    
    public int getWindowSize()
    {
        return windowSize;
    }
    
    @Override
    public void handle(Message msg, Buffer buf) throws SSHException
    {
        if (msg.in(91, 100))
            getChannel(buf).handle(msg, buf);
        
        else if (msg.in(80, 90))
            switch (msg)
            {
            case REQUEST_SUCCESS:
                gotResponse(buf);
                break;
            case REQUEST_FAILURE:
                gotResponse(null);
                break;
            case CHANNEL_OPEN:
                gotChannelOpen(buf);
                break;
            default:
                trans.sendUnimplemented();
            }
        
        else
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR, "Not a connection layer packet");
    }
    
    public synchronized void join() throws InterruptedException
    {
        while (!channels.isEmpty())
            wait();
    }
    
    public int nextID()
    {
        return nextID.getAndIncrement();
    }
    
    @Override
    public void notifyError(SSHException error)
    {
        super.notifyError(error);
        ErrorNotifiable.Util.alertAll(error, globalReqs.toArray());
        ErrorNotifiable.Util.alertAll(error, channels.values().toArray());
        globalReqs.clear();
        channels.clear();
    }
    
    public void notifyUnimplemented(int seqNum) throws ConnectionException
    {
        throw new ConnectionException("Unexpected SSH_MSG_UNIMPLEMENTED");
    }
    
    public synchronized Future<Buffer, ConnectionException> sendGlobalRequest(String name, boolean wantReply,
            Buffer specifics) throws TransportException
    {
        log.info("Making global request for `{}`", name);
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
    
    public void sendOpenFailure(int recipient, Reason reason, String message) throws TransportException
    {
        trans.writePacket(new Buffer(Message.CHANNEL_OPEN_FAILURE) //
                                                                  .putInt(recipient) //
                                                                  .putInt(reason.getCode()) //
                                                                  .putString(message));
    }
    
    public void setMaxPacketSize(int maxPacketSize)
    {
        this.maxPacketSize = maxPacketSize;
    }
    
    public void setWindowSize(int windowSize)
    {
        this.windowSize = windowSize;
    }
    
    protected Channel getChannel(Buffer buffer) throws ConnectionException
    {
        int recipient = buffer.getInt();
        Channel channel = get(recipient);
        if (channel == null) {
            buffer.rpos(buffer.rpos() - 5);
            Constants.Message msg = buffer.getMessageID();
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR, "Received " + msg + " on unknown channel #"
                    + recipient);
        }
        return channel;
    }
    
    protected void gotChannelOpen(Buffer buf) throws ConnectionException, TransportException
    {
        String type = buf.getString();
        log.debug("Received CHANNEL_OPEN for `{}` channel", type);
        if (openers.containsKey(type))
            openers.get(type).handleOpen(buf);
        else {
            log.warn("No opener found for `{}` CHANNEL_OPEN request -- rejecting", type);
            sendOpenFailure(buf.getInt(), OpenFailException.Reason.UNKNOWN_CHANNEL_TYPE, "");
        }
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
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR,
                                          "Got a global request response when none was requested");
    }
    
}
