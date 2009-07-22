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

import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicBoolean;
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
public abstract class AbstractChannel implements Channel, Closeable
{
    
    protected static final int TIMEOUT = 15;
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    protected final Queue<Event<ConnectionException>> chanReqs = new LinkedList<Event<ConnectionException>>();
    
    protected final LocalWindow localWin = new LocalWindow(this);
    protected final RemoteWindow remoteWin = new RemoteWindow();
    
    protected int id;
    protected Transport trans;
    
    protected ChannelInputStream in = new ChannelInputStream(localWin);
    protected ChannelOutputStream out = new ChannelOutputStream(this, remoteWin);
    
    private final AtomicBoolean eofSent = new AtomicBoolean();
    private final AtomicBoolean closeReqd = new AtomicBoolean();
    
    private final ReentrantLock lock = new ReentrantLock();
    
    protected Event<ConnectionException> open;
    protected Event<ConnectionException> close;
    
    protected int recipient;
    
    public synchronized void close() throws ConnectionException, TransportException
    {
        sendClose();
        close.await(TIMEOUT);
    }
    
    public int getID()
    {
        return id;
    }
    
    public InputStream getInputStream()
    {
        return in;
    }
    
    public OutputStream getOutputStream()
    {
        return out;
    }
    
    public int getRecipient()
    {
        return recipient;
    }
    
    public Transport getTransport()
    {
        return trans;
    }
    
    public boolean handle(Message cmd, Buffer buf) throws ConnectionException, TransportException
    {
        lock.lock();
        try {
            switch (cmd)
            {
                case CHANNEL_OPEN_CONFIRMATION:
                {
                    recipient = buf.getInt();
                    remoteWin.init(buf.getInt(), buf.getInt());
                    open.set();
                    break;
                }
                case CHANNEL_OPEN_FAILURE:
                {
                    open.error(new ChannelOpenFailureException(getType(), buf.getInt(), buf.getString()));
                    return true;
                }
                case CHANNEL_WINDOW_ADJUST:
                {
                    log.info("Received SSH_MSG_CHANNEL_WINDOW_ADJUST on channel {}", id);
                    remoteWin.expand(buf.getInt());
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
                    gotResponse(true);
                    break;
                }
                case CHANNEL_FAILURE:
                {
                    gotResponse(false);
                    break;
                }
                case CHANNEL_EOF:
                {
                    eofInputStreams();
                    break;
                }
                case CHANNEL_CLOSE:
                {
                    log.debug("Received SSH_MSG_CHANNEL_CLOSE on channel #{}", id);
                    sendClose();
                    close.set();
                    closeStreams();
                    return true;
                }
                default:
                {
                    trans.sendUnimplemented();
                    break;
                }
            }
        } finally {
            lock.unlock();
        }
        
        return false;
    }
    
    public void init(Transport trans, int id, int localWinSize, int localMaxPacketSize)
    {
        this.trans = trans;
        this.id = id;
        open = newEvent("open");
        close = newEvent("close");
        localWin.init(localWinSize, localMaxPacketSize);
    }
    
    public boolean isOpen()
    {
        lock.lock();
        try {
            return open.isSet() && !open.hasWaiters() && !(close.isSet() || close.hasWaiters());
        } finally {
            lock.unlock();
        }
    }
    
    @SuppressWarnings("unchecked")
    public void notifyError(SSHException exception)
    {
        Event.Util.<ConnectionException> notifyError(exception, open, close);
        Event.Util.<ConnectionException> notifyError(exception, chanReqs);
    }
    
    public void open() throws ConnectionException, TransportException
    {
        lock.lock();
        try {
            if (!open.isSet()) {
                trans.writePacket(buildOpenReq());
                open.await(TIMEOUT);
            }
        } finally {
            lock.unlock();
        }
    }
    
    public void sendEOF() throws TransportException
    {
        if (!eofSent.getAndSet(true) && !closeReqd.get())
            try {
                log.info("Sending SSH_MSG_CHANNEL_EOF on channel {}", id);
                trans.writePacket(new Buffer(Constants.Message.CHANNEL_EOF).putInt(recipient));
            } finally {
                out.close();
            }
    }
    
    private void gotResponse(boolean success) throws ConnectionException
    {
        Event<ConnectionException> event = chanReqs.poll();
        if (event != null) {
            if (success)
                event.set();
            else
                event.error("Request failed");
        } else
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR,
                                          "Received channel resonse without a corresponding request");
    }
    
    protected Buffer buildOpenReq()
    {
        return new Buffer(Message.CHANNEL_OPEN) //
                                               .putString(getType()) //
                                               .putInt(id) //
                                               .putInt(localWin.getSize()) //
                                               .putInt(localWin.getMaxPacketSize());
    }
    
    protected void closeStreams()
    {
        IOUtils.closeQuietly(in, out);
    }
    
    protected void doWrite(Buffer buf, ChannelInputStream stream) throws ConnectionException, TransportException
    {
        int len = buf.getInt();
        if (len < 0 || len > 32768)
            throw new IllegalStateException("Bad item length: " + len);
        log.debug("Received data on channel {}", id);
        if (log.isTraceEnabled())
            log.trace("Received channel extended data: {}", BufferUtils.printHex(buf.array(), buf.rpos(), len));
        stream.receive(buf.array(), buf.rpos(), len);
    }
    
    protected void eofInputStreams()
    {
        in.eof();
    }
    
    protected void handleExtendedData(int dataTypeCode, Buffer buf) throws ConnectionException, TransportException
    {
        throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR, "Extended data not supported on " + getType()
                + " channel");
    }
    
    protected void handleRequest(String reqType, Buffer buf) throws ConnectionException, TransportException
    {
        trans.writePacket(new Buffer(Message.CHANNEL_FAILURE));
    }
    
    protected Buffer newBuffer(Message cmd)
    {
        return new Buffer(cmd).putInt(recipient);
    }
    
    protected Event<ConnectionException> newEvent(String name)
    {
        return new Event<ConnectionException>("chan#" + id + " - " + name, ConnectionException.chainer, lock);
    }
    
    protected synchronized Event<ConnectionException> sendChannelRequest(String reqType, boolean wantReply,
            Buffer reqSpecific) throws TransportException
    {
        Buffer reqBuf = newBuffer(Message.CHANNEL_REQUEST).putString(reqType) //
                                                          .putBoolean(wantReply) //
                                                          .putBuffer(reqSpecific);
        log.info("Sending SSH_MSG_CHANNEL_REQUEST on channel #{} for {}", id, reqType);
        trans.writePacket(reqBuf);
        Event<ConnectionException> event = null;
        if (wantReply) {
            event = newEvent("channel request - " + reqType);
            chanReqs.add(event);
        }
        return event;
    }
    
    protected void sendClose()
    {
        if (!closeReqd.getAndSet(true)) {
            log.info("Sending SSH_MSG_CHANNEL_CLOSE for channel #{}", id);
            IOUtils.writeQuietly(trans, newBuffer(Message.CHANNEL_CLOSE));
        }
    }
    
}
