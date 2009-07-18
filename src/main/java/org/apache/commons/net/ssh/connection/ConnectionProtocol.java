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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.net.ssh.AbstractService;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Constants.Message;

/**
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class ConnectionProtocol extends AbstractService implements ConnectionService
{
    
    public static final int WINDOW_START_SIZE = 0x200000;
    public static final int MAX_PACKET_SIZE = 0x8000;
    
    protected final Map<Integer, Channel> channels = new ConcurrentHashMap<Integer, Channel>();
    protected int nextChannelID;
    
    public ConnectionProtocol(Transport session)
    {
        super(session);
    }
    
    public String getName()
    {
        return NAME;
    }
    
    public void handle(Message cmd, Buffer buffer) throws SSHException
    {
        int num = cmd.toInt();
        if (num < 80 || num > 100)
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR);
        else if (num < 90) { // global
        
        } else { // channel-specific
            Channel chan = getChannel(buffer);
            if (chan.handle(cmd, buffer))
                forget(chan.getID());
        }
    }
    
    public void notifyError(SSHException ex)
    {
        for (Channel chan : channels.values())
            chan.notifyError(ex);
        channels.clear();
    }
    
    public void notifyUnimplemented(int seqNum) throws ConnectionException
    {
        throw new ConnectionException("Unexpected SSH_MSG_UNIMPLEMENTED");
    }
    
    public Session startSession() throws ChannelOpenFailureException, ConnectionException, TransportException
    {
        return (Session) initChannel(new SessionChannel());
    }
    
    private int add(Channel chan)
    {
        int id = ++nextChannelID;
        channels.put(id, chan);
        return id;
    }
    
    private void forget(int id)
    {
        channels.remove(id);
    }
    
    private Channel getChannel(Buffer buffer) throws ConnectionException
    {
        int recipient = buffer.getInt();
        Channel channel = channels.get(recipient);
        if (channel == null) {
            buffer.rpos(buffer.rpos() - 5);
            Constants.Message cmd = buffer.getCommand();
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR, "Received " + cmd + " on unknown channel "
                    + recipient);
        }
        return channel;
    }
    
    private Channel initChannel(Channel chan) throws ChannelOpenFailureException, ConnectionException,
            TransportException
    {
        chan.init(trans, add(chan), WINDOW_START_SIZE, MAX_PACKET_SIZE);
        chan.open();
        return chan;
    }
    
}
