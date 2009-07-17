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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;
import org.apache.commons.net.ssh.util.StateMachine;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Access should be externally synchronized.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractChannel implements Channel
{
    
    private enum State
    {
        /** Something has been requested */
        REQ,
        /** All well */
        DEFAULT,
    }
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    private final StateMachine<State, ConnectionException> sm =
            new StateMachine<State, ConnectionException>(log, this, ConnectionException.chainer);
    
    protected Transport trans;
    
    protected final Window localWindow = new Window(this, true);
    protected final Window remoteWindow = new Window(this, false);
    protected final String type;
    protected int id;
    protected int recipient;
    
    // TODO figure this out
    protected InputStream in;
    protected OutputStream out;
    protected InputStream err;
    
    protected AbstractChannel(String type)
    {
        this.type = type;
    }
    
    public void close() throws TransportException
    {
        if (sm.notIn((State) null)) {
            sm.transition(State.REQ);
            trans.writePacket(new Buffer(Message.CHANNEL_CLOSE).putInt(id));
            sm.transition(null);
        }
    }
    
    public InputStream getErr()
    {
        return err;
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
    
    public int getRecipient()
    {
        return recipient;
    }
    
    public Transport getTransport()
    {
        return trans;
    }
    
    public boolean handle(Constants.Message cmd, Buffer buf) throws ConnectionException, TransportException
    {
        switch (cmd)
        {
        case CHANNEL_OPEN_CONFIRMATION:
            log.info("Received SSH_MSG_CHANNEL_OPEN_CONFIRMATION on channel {}", id);
            sm.assertIn(State.REQ);
            recipient = buf.getInt();
            remoteWindow.init(buf.getInt(), buf.getInt());
            sm.transition(State.DEFAULT);
            break;
        case CHANNEL_WINDOW_ADJUST:
            log.info("Received SSH_MSG_CHANNEL_WINDOW_ADJUST on channel {}", id);
            remoteWindow.expand(buf.getInt());
            break;
        case CHANNEL_OPEN_FAILURE:
            log.info("Received SSH_MSG_CHANNEL_OPEN_FAILURE on channel {}", id);
            sm.assertIn(State.REQ);
            sm.interrupt(new ChannelOpenFailureException(type, buf.getInt()));
            return true;
        case CHANNEL_CLOSE:
            close();
            return true;
        case CHANNEL_SUCCESS:
            sm.assertIn(State.REQ);
            sm.transition(State.DEFAULT);
            break;
        case CHANNEL_FAILURE:
            sm.assertIn(State.REQ);
            sm.interrupt(new ConnectionException("Request failed"));
            sm.transition(State.DEFAULT);
            break;
        case CHANNEL_REQUEST:
            String reqType = buf.getString();
            buf.getBoolean(); // we don't reply to requests
            log.info("Received SSH_MSG_CHANNEL_REQUEST on channel #{} for [{}]", id, reqType);
            handleRequest(reqType, buf);
        default:
            assert false;
        }
        return false;
    }
    
    public void init(Transport trans, int id, int windowSize, int maxPacketSize)
    {
        this.trans = trans;
        this.id = id;
        localWindow.init(windowSize, maxPacketSize);
    }
    
    public boolean isOpen()
    {
        return sm.notIn((State) null);
    }
    
    //    public void handleData(Buffer buffer) throws ConnectionException
    //    {
    //        int len = buffer.getInt();
    //        if (len < 0 || len > 32768)
    //            throw new IllegalStateException("Bad item length: " + len);
    //        log.debug("Received SSH_MSG_CHANNEL_DATA on channel {}", id);
    //        if (log.isTraceEnabled())
    //            log.trace("Received channel data: {}", BufferUtils.printHex(buffer.array(), buffer.rpos(), len));
    //        try {
    //            doWriteData(buffer.array(), buffer.rpos(), len);
    //        } catch (IOException e) {
    //            throw new ConnectionException(e);
    //        }
    //    }
    //    
    //    public void handleEOF() throws ConnectionException
    //    {
    //        log.info("Received SSH_MSG_CHANNEL_EOF on channel {}", id);
    //        
    //    }
    
    //    public void handleExtendedData(Buffer buffer) throws ConnectionException, TransportException
    //    {
    //        int dataTypeCode = buffer.getInt();
    //        // Only accept extended data for stderr
    //        if (dataTypeCode != 1) {
    //            log.info("Send SSH_MSG_CHANNEL_FAILURE on channel {}", id);
    //            trans.writePacket(new Buffer(Constants.Message.CHANNEL_FAILURE).putInt(recipient));
    //            return;
    //        }
    //        int len = buffer.getInt();
    //        if (len < 0 || len > 32768)
    //            throw new IllegalStateException("Bad item length: " + len);
    //        log.debug("Received SSH_MSG_CHANNEL_EXTENDED_DATA on channel {}", id);
    //        if (log.isTraceEnabled())
    //            log.trace("Received channel extended data: {}", BufferUtils.printHex(buffer.array(), buffer.rpos(), len));
    //        try {
    //            doWriteExtendedData(buffer.array(), buffer.rpos(), len);
    //        } catch (IOException e) {
    //            throw new ConnectionException(e);
    //        }
    //    }
    
    //    public void handleFailure() throws IOException
    //    {
    //        log.info("Received SSH_MSG_CHANNEL_FAILURE on channel {}", id);
    //        // TODO: do something to report failed requests?
    //    }
    
    public void notifyError(SSHException exception)
    {
        sm.interrupt(exception);
    }
    
    public void open() throws ChannelOpenFailureException, ConnectionException, TransportException
    {
        sm.transition(State.REQ);
        trans.writePacket(buildOpenRequest());
        sm.await(State.DEFAULT);
    }
    
    protected Buffer buildOpenRequest()
    {
        return new Buffer(Message.CHANNEL_OPEN) //
                                               .putString(type) //
                                               .putInt(id) //
                                               .putInt(localWindow.getSize()) //
                                               .putInt(localWindow.getPacketSize());
    }
    
    protected abstract void handleRequest(String reqType, Buffer buf);
    
    protected final Buffer makeReqBuf(String reqType, boolean wantReply)
    {
        return new Buffer(Message.CHANNEL_REQUEST). //
                                                  putInt(recipient). //
                                                  putString(reqType). //
                                                  putBoolean(wantReply);
    }
    
    //    
    //    protected void doWriteData(byte[] data, int off, int len) throws IOException
    //    {
    //        if (out != null) {
    //            out.write(data, off, len);
    //            out.flush();
    //        }
    //        localWindow.consumeAndCheck(len);
    //    }
    //    
    //    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException // TODO
    //    {
    //        if (err != null) {
    //            //err.write(data, off, len);
    //        }
    //        localWindow.consumeAndCheck(len);
    //    }
    //
    
    protected synchronized void request(Buffer reqBuf) throws ConnectionException, TransportException
    {
        sm.assertIn(State.DEFAULT);
        sm.transition(State.REQ);
        trans.writePacket(reqBuf);
        sm.await(State.DEFAULT);
    }
    
    protected void sendEOF() throws TransportException
    {
        log.info("Send SSH_MSG_CHANNEL_EOF on channel {}", id);
        trans.writePacket(new Buffer(Constants.Message.CHANNEL_EOF).putInt(recipient));
    }
    
    protected void sendWindowAdjust(int len) throws IOException // ok
    {
        log.info("Send SSH_MSG_CHANNEL_WINDOW_ADJUST on channel {}", id);
        trans.writePacket(new Buffer(Constants.Message.CHANNEL_WINDOW_ADJUST).putInt(recipient).putInt(len));
    }
    
}
