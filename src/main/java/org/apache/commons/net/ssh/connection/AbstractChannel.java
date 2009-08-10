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
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.ErrorNotifiable;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.BufferUtils;
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
    
    protected final Logger log;
    
    protected final Transport trans;
    protected final Connection conn;
    
    protected final LocalWindow lwin = new LocalWindow(this);
    protected final RemoteWindow rwin = new RemoteWindow(this);
    
    protected final ChannelInputStream in = new ChannelInputStream(this, lwin);
    protected final ChannelOutputStream out = new ChannelOutputStream(this, rwin);
    
    protected final Queue<Event<ConnectionException>> chanReqResponseEvents =
            new LinkedList<Event<ConnectionException>>();
    
    protected final ReentrantLock lock = new ReentrantLock();
    protected final Event<ConnectionException> open;
    protected final Event<ConnectionException> close;
    
    protected final String type;
    protected final int id;
    protected int recipient;
    
    protected boolean eofSent;
    protected boolean eofGot;
    protected boolean closeReqd;
    
    protected AbstractChannel(String type, Connection conn)
    {
        this.type = type;
        this.conn = conn;
        this.trans = conn.getTransport();
        id = conn.nextID();
        lwin.init(conn.getWindowSize(), conn.getMaxPacketSize());
        log = LoggerFactory.getLogger("chan#" + id);
        open = newEvent("open");
        close = newEvent("close");
    }
    
    public void close() throws ConnectionException, TransportException
    {
        lock.lock();
        try {
            if (!close.isSet()) {
                try {
                    sendClose();
                } catch (TransportException e) {
                    if (!close.hasError())
                        throw e;
                }
                try {
                    close.await(conn.getTimeout());
                } finally {
                    finishOff();
                }
            }
        } finally {
            lock.unlock();
        }
    }
    
    public int getID()
    {
        return id;
    }
    
    public InputStream getInputStream()
    {
        return in;
    }
    
    public int getLocalMaxPacketSize()
    {
        return lwin.getMaxPacketSize();
    }
    
    public int getLocalWinSize()
    {
        return lwin.getSize();
    }
    
    public OutputStream getOutputStream()
    {
        return out;
    }
    
    public int getRecipient()
    {
        return recipient;
    }
    
    public int getRemoteMaxPacketSize()
    {
        return rwin.getMaxPacketSize();
    }
    
    public int getRemoteWinSize()
    {
        return rwin.getSize();
    }
    
    public Transport getTransport()
    {
        return trans;
    }
    
    public String getType()
    {
        return type;
    }
    
    public void handle(Message msg, Buffer buf) throws ConnectionException, TransportException
    {
        switch (msg)
        {
        
        case CHANNEL_DATA:
            doWrite(buf, in);
            break;
        
        case CHANNEL_EXTENDED_DATA:
            gotExtendedData(buf.getInt(), buf);
            break;
        
        case CHANNEL_WINDOW_ADJUST:
            gotWindowAdjustment(buf.getInt());
            break;
        
        case CHANNEL_REQUEST:
            gotChannelRequest(buf);
            break;
        
        case CHANNEL_SUCCESS:
            gotResponse(true);
            break;
        
        case CHANNEL_FAILURE:
            gotResponse(false);
            break;
        
        case CHANNEL_EOF:
            gotEOF();
            break;
        
        case CHANNEL_CLOSE:
            gotClose();
            break;
        
        default:
            gotUnknown(msg, buf);
            
        }
    }
    
    public void init(int recipient, int remoteWinSize, int remoteMaxPacketSize)
    {
        this.recipient = recipient;
        rwin.init(remoteWinSize, remoteMaxPacketSize);
        out.init();
        log.info("Initialized - {}", this);
    }
    
    public synchronized boolean isOpen()
    {
        lock.lock();
        try {
            return open.isSet() && !close.isSet() && !closeReqd;
        } finally {
            lock.unlock();
        }
    }
    
    public void notifyError(SSHException error)
    {
        log.debug("Channel #{} got notified of {}", getID(), error.toString());
        ErrorNotifiable.Util.alertAll(error, open, close, in, out);
        ErrorNotifiable.Util.alertAll(error, (ErrorNotifiable[]) chanReqResponseEvents.toArray());
        finishOff();
    }
    
    public synchronized void sendEOF() throws TransportException
    {
        try {
            if (!closeReqd && !eofSent) {
                log.info("Sending EOF");
                trans.writePacket(newBuffer(Message.CHANNEL_EOF));
                if (eofGot)
                    sendClose();
            }
        } finally {
            eofSent = true;
        }
    }
    
    @Override
    public String toString()
    {
        return "< " + type + " channel: id=" + id + ", recipient=" + recipient + ", localWin=" + lwin + ", remoteWin="
                + rwin + " >";
    }
    
    private void gotClose() throws TransportException
    {
        log.info("Got close");
        try {
            closeStreams();
            sendClose();
        } finally {
            finishOff();
        }
    }
    
    private void gotWindowAdjustment(int howmuch)
    {
        log.info("Received window adjustment for {} bytes", howmuch);
        rwin.expand(howmuch);
    }
    
    protected void closeStreams()
    {
        IOUtils.closeQuietly(in, out);
    }
    
    protected void doWrite(Buffer buf, ChannelInputStream stream) throws ConnectionException, TransportException
    {
        int len = buf.getInt();
        if (len < 0 || len > getLocalMaxPacketSize())
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR, "Bad item length: " + len);
        if (log.isTraceEnabled())
            log.trace("IN: {}", BufferUtils.printHex(buf.array(), buf.rpos(), len));
        stream.receive(buf.array(), buf.rpos(), len);
    }
    
    protected void finishOff()
    {
        conn.forget(this);
        close.set();
    }
    
    protected void gotChannelRequest(Buffer buf) throws ConnectionException, TransportException
    {
        String reqType = buf.getString();
        buf.getBoolean(); // We don't care about the 'want-reply' value
        log.info("Got request for `{}`", reqType);
        handleRequest(reqType, buf);
    }
    
    protected synchronized void gotEOF() throws TransportException
    {
        log.info("Got EOF");
        eofGot = true;
        in.eof();
        if (eofSent)
            sendClose();
    }
    
    protected void gotExtendedData(int dataTypeCode, Buffer buf) throws ConnectionException, TransportException
    {
        throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR, "Extended data not supported on " + type
                + " channel");
    }
    
    protected synchronized void gotResponse(boolean success) throws ConnectionException
    {
        Event<ConnectionException> responseEvent = chanReqResponseEvents.poll();
        if (responseEvent != null) {
            if (success)
                responseEvent.set();
            else
                responseEvent.error("Request failed");
        } else
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR,
                                          "Received response to channel request when none was requested");
    }
    
    protected void gotUnknown(Message msg, Buffer buf) throws ConnectionException, TransportException
    {
        trans.sendUnimplemented();
    }
    
    /**
     * Subclasses can override this method to handle specific requests.
     * 
     * @param reqType
     * @param buf
     * @throws ConnectionException
     * @throws TransportException
     */
    protected void handleRequest(String reqType, Buffer buf) throws ConnectionException, TransportException
    {
        trans.writePacket(newBuffer(Message.CHANNEL_FAILURE));
    }
    
    protected Buffer newBuffer(Message cmd)
    {
        return new Buffer(cmd).putInt(recipient);
    }
    
    protected Event<ConnectionException> newEvent(String name)
    {
        return new Event<ConnectionException>("chan#" + id + " / " + name, ConnectionException.chainer, lock);
    }
    
    protected synchronized Event<ConnectionException> sendChannelRequest(String reqType, boolean wantReply,
            Buffer reqSpecific) throws TransportException
    {
        log.info("Sending channel request for `{}`", reqType);
        trans.writePacket(newBuffer(Message.CHANNEL_REQUEST).putString(reqType) //
                                                            .putBoolean(wantReply) //
                                                            .putBuffer(reqSpecific));
        
        Event<ConnectionException> responseEvent = null;
        if (wantReply) {
            responseEvent = newEvent("chanreq for " + reqType);
            chanReqResponseEvents.add(responseEvent);
        }
        return responseEvent;
    }
    
    protected synchronized void sendClose() throws TransportException
    {
        try {
            if (!closeReqd) {
                log.info("Sending close");
                trans.writePacket(newBuffer(Message.CHANNEL_CLOSE));
            }
        } finally {
            closeReqd = true;
        }
    }
    
}
