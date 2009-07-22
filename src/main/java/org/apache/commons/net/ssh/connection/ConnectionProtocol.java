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
    
    public class GlobalReq extends Future<Buffer, ConnectionException>
    {
        GlobalReq(String name, boolean wantReply, Buffer specific) throws TransportException
        {
            super("global req for " + name, ConnectionException.chainer, null);
            trans.writePacket(new Buffer(Message.GLOBAL_REQUEST) //
                                                                .putString(name) //
                                                                .putBoolean(wantReply) //
                                                                .putBuffer(specific)); //
        }
    }
    
    public static final int WINDOW_SIZE = 0x200000;
    public static final int MAX_PACKET_SIZE = 0x8800;
    
    protected final Map<Integer, Channel> channels = new ConcurrentHashMap<Integer, Channel>();
    protected Map<String, ChannelOpener> handlers = new ConcurrentHashMap<String, ChannelOpener>();
    
    private int nextID;
    
    protected final Lock lock = new ReentrantLock();
    protected Queue<GlobalReq> globalReqs = new LinkedList<GlobalReq>();
    
    public ConnectionProtocol(Transport session)
    {
        super(session);
    }
    
    public int getMaxPacketSize()
    {
        return MAX_PACKET_SIZE;
    }
    
    public String getName()
    {
        return NAME;
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
                    gotResponse(new Buffer(buf.getCompactData()));
                    break;
                case REQUEST_FAILURE:
                    gotResponse(null);
                    break;
                case CHANNEL_OPEN:
                    ChannelOpener handler = handlers.get(buf.getString());
                    if (handler != null)
                        handler.handleReq(this, buf);
                    else
                        trans.writePacket(new Buffer(Message.REQUEST_FAILURE));
                    break;
                default:
                    trans.sendUnimplemented();
            }
        else {
            Channel chan = getChannel(buf);
            if (chan.handle(cmd, buf))
                forget(chan.getID());
        }
    }
    
    public synchronized void initAndAdd(Channel chan)
    {
        int id = nextID++;
        chan.init(trans, id, WINDOW_SIZE, MAX_PACKET_SIZE);
        channels.put(id, chan);
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
    
    //        public int startRemoteForwarding(String addressToBind, int portToBind) throws TransportException,
    //                ConnectionException
    //        {
    //            int port =
    //                    new GlobalReq(PF, true, new Buffer().putString(addressToBind).putInt(portToBind)).get(TIMEOUT).getInt();
    //            //handlers.put(PF, value);
    //            return port;
    //        }
    
    public void notifyUnimplemented(int seqNum) throws ConnectionException
    {
        throw new ConnectionException("Unexpected SSH_MSG_UNIMPLEMENTED");
    }
    
    public Session startSession() throws ChannelOpenFailureException, ConnectionException, TransportException
    {
        SessionChannel sess = new SessionChannel();
        initAndAdd(sess);
        sess.open();
        return sess;
    }
    
    private void forget(int id)
    {
        channels.remove(id);
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
    
    protected void gotResponse(Buffer response) throws ConnectionException
    {
        GlobalReq gr = globalReqs.poll();
        if (gr != null) {
            if (response != null)
                gr.set(response);
            else
                gr.error("Global request failed");
        } else
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR);
    }
    
}
