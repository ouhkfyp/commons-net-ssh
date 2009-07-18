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

import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.BufferUtils;
import org.apache.commons.net.ssh.util.Constants;
import org.apache.commons.net.ssh.util.Event;
import org.apache.commons.net.ssh.util.IOUtils;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public abstract class AbstractChannel implements Channel
{
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    protected Transport trans;
    
    protected final Window localWindow = new Window(this, true);
    protected final Window remoteWindow = new Window(this, false);
    protected final String type;
    protected int id;
    protected int recipient;
    
    protected final Queue<Event<ConnectionException>> chanReqs = new LinkedList<Event<ConnectionException>>();
    
    protected ChannelInputStream in = new ChannelInputStream(localWindow);
    protected ChannelOutputStream out = new ChannelOutputStream(this, remoteWindow, log);
    
    private boolean eofSent;
    private boolean closeReqd;
    
    private Event<ConnectionException> opened;
    private Event<ConnectionException> closed;
    
    private final Lock lock = new ReentrantLock();
    
    protected AbstractChannel(String type)
    {
        this.type = type;
    }
    
    public void close() throws ConnectionException, TransportException
    {
        lock.lock();
        try {
            if (!closeReqd) {
                closeReqd = true;
                trans.writePacket(new Buffer(Message.CHANNEL_CLOSE).putInt(id));
                closed.await();
                closeStreams();
            }
        } finally {
            lock.unlock();
        }
    }
    
    public int getID()
    {
        return id;
    }
    
    public InputStream getIn()
    {
        return in;
    }
    
    public Window getLocalWindow()
    {
        return localWindow;
    }
    
    public OutputStream getOut()
    {
        return out;
    }
    
    public boolean handle(Constants.Message cmd, Buffer buf) throws ConnectionException, TransportException
    {
        
        boolean forget = false; // return value -- indicates whether ConnectionProtocol should forget this channel
        lock.lock();
        try {
            
            if (opened.hasWaiter())
                
                switch (cmd)
                {
                    case CHANNEL_OPEN_CONFIRMATION:
                    {
                        log.info("Received SSH_MSG_CHANNEL_OPEN_CONFIRMATION on channel {}", id);
                        recipient = buf.getInt();
                        remoteWindow.init(buf.getInt(), buf.getInt());
                        opened.set();
                        break;
                    }
                    case CHANNEL_OPEN_FAILURE:
                    {
                        log.info("Received SSH_MSG_CHANNEL_OPEN_FAILURE on channel {}", id);
                        opened.error(new ChannelOpenFailureException(type, buf.getInt()));
                        forget = true;
                        break;
                    }
                    default:
                    {
                        trans.sendUnimplemented();
                        break;
                    }
                }
            
            else if (opened.isSet())
                
                switch (cmd)
                {
                    
                    case CHANNEL_WINDOW_ADJUST:
                    {
                        log.info("Received SSH_MSG_CHANNEL_WINDOW_ADJUST on channel {}", id);
                        remoteWindow.expand(buf.getInt());
                        break;
                    }
                    case CHANNEL_DATA:
                    {
                        doWrite(buf, in);
                        break;
                    }
                    case CHANNEL_EXTENDED_DATA:
                    {
                        handleExtendedData(buf.getInt(), buf);
                        break;
                    }
                        
                    case CHANNEL_REQUEST:
                    {
                        String reqType = buf.getString();
                        buf.getBoolean(); // we don't ever reply to requests, so ignore this value
                        log.info("Received SSH_MSG_CHANNEL_REQUEST on channel #{} for [{}]", id, reqType);
                        handleRequest(reqType, buf);
                        break;
                    }
                    case CHANNEL_SUCCESS:
                    {
                        gotReqReply(true);
                        break;
                    }
                    case CHANNEL_FAILURE:
                    {
                        gotReqReply(false);
                        break;
                    }
                        
                    case CHANNEL_EOF:
                    {
                        gotEOF();
                        break;
                    }
                    case CHANNEL_CLOSE:
                    {
                        closed.set();
                        close();
                        forget = true;
                        break;
                    }
                    default:
                    {
                        trans.sendUnimplemented();
                        break;
                    }
                }
            
            else
                assert false;
            
            return forget;
            
        } finally {
            lock.unlock();
        }
    }
    
    public void init(Transport trans, int id, int windowSize, int maxPacketSize)
    {
        this.trans = trans;
        this.id = id;
        opened = newEvent("channel #" + id + " / opened");
        closed = newEvent("channel #" + id + " / closed");
        localWindow.init(windowSize, maxPacketSize);
    }
    
    public boolean isOpen()
    {
        return opened.isSet();
    }
    
    @SuppressWarnings("unchecked")
    public void notifyError(SSHException exception)
    {
        Event.Util.<ConnectionException> notifyError(exception, opened, closed);
        Event.Util.<ConnectionException> notifyError(exception, chanReqs);
    }
    
    public void open() throws ChannelOpenFailureException, ConnectionException, TransportException
    {
        lock.lock();
        try {
            trans.writePacket(buildOpenRequest());
            opened.await();
        } finally {
            lock.unlock();
        }
    }
    
    public void sendEOF() throws TransportException
    {
        lock.lock();
        try {
            if (!eofSent) {
                eofSent = true;
                try {
                    log.info("Sending SSH_MSG_CHANNEL_EOF on channel {}", id);
                    trans.writePacket(new Buffer(Constants.Message.CHANNEL_EOF).putInt(recipient));
                } finally {
                    closeStreams();
                }
            }
        } finally {
            lock.unlock();
        }
    }
    
    private void gotReqReply(boolean success) throws ConnectionException
    {
        Event<ConnectionException> event = chanReqs.poll();
        log.info("Channel request {} successful={}", event, success);
        if (event != null) {
            if (success)
                event.set();
            else
                event.error("Request failed");
        } else
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR,
                                          "Received channel resonse without a corresponding request");
    }
    
    /** Sub-classes can override and add-on their specific stuff */
    protected Buffer buildOpenRequest()
    {
        return new Buffer(Message.CHANNEL_OPEN) //
                                               .putString(type) //
                                               .putInt(id) //
                                               .putInt(localWindow.getSize()) //
                                               .putInt(localWindow.getPacketSize());
    }
    
    protected void closeStreams()
    {
        IOUtils.closeQuietly(in, out);
    }
    
    protected void doWrite(Buffer buf, ChannelInputStream out) throws ConnectionException, TransportException
    {
        int len = buf.getInt();
        if (len < 0 || len > 32768)
            throw new IllegalStateException("Bad item length: " + len);
        log.debug("Received data on channel {}", id);
        if (log.isTraceEnabled())
            log.trace("Received channel extended data: {}", BufferUtils.printHex(buf.array(), buf.rpos(), len));
        out.receive(buf.array(), buf.rpos(), len);
    }
    
    protected void gotEOF() throws TransportException
    {
        in.setEOF();
        sendEOF();
    }
    
    protected abstract void handleExtendedData(int dataTypeCode, Buffer buf) throws ConnectionException,
            TransportException;
    
    protected abstract void handleRequest(String reqType, Buffer buf);
    
    /**
     * 
     * @param reqType
     * @param wantReply
     * @param specific
     *            request-specific fields should be put in this buffer
     * @return
     * @throws TransportException
     */
    protected synchronized Event<ConnectionException> sendChannelRequest(String reqType, boolean wantReply,
            Buffer specific) throws TransportException
    {
        Buffer reqBuf = new Buffer(Message.CHANNEL_REQUEST).putInt(recipient).putString(reqType).putBoolean(wantReply);
        if (specific != null)
            reqBuf.putBuffer(specific);
        log.info("Sending SSH_MSG_CHANNEL_REQUEST on channel #{} for {}", id, reqType);
        trans.writePacket(reqBuf);
        Event<ConnectionException> event = null;
        if (wantReply) {
            event = newEvent(reqType);
            chanReqs.add(event);
        }
        return event;
    }
    
    protected void sendWindowAdjust(int len) throws TransportException
    {
        log.info("Send SSH_MSG_CHANNEL_WINDOW_ADJUST on channel {}", id);
        trans.writePacket(new Buffer(Constants.Message.CHANNEL_WINDOW_ADJUST).putInt(recipient).putInt(len));
    }
    
    Event<ConnectionException> newEvent(String name)
    {
        return new Event<ConnectionException>(name, ConnectionException.chainer, lock);
    }
    
}
