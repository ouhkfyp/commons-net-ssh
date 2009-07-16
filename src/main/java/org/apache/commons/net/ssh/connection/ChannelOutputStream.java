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
import java.io.OutputStream;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;
import org.slf4j.Logger;

/**
 * TODO Add javadoc
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelOutputStream extends OutputStream
{
    
    private final AbstractChannel channel;
    private final Window remoteWindow;
    private final Logger log;
    private final Constants.Message cmd;
    private final byte[] b = new byte[1];
    private Buffer buffer;
    private boolean closed;
    private int bufferLength;
    
    public ChannelOutputStream(AbstractChannel channel, Window remoteWindow, Logger log, Constants.Message cmd)
    {
        this.channel = channel;
        this.remoteWindow = remoteWindow;
        this.log = log;
        this.cmd = cmd;
        newBuffer();
    }
    
    @Override
    public synchronized void close() throws IOException
    {
        closed = true;
    }
    
    @Override
    public synchronized void flush() throws IOException
    {
        if (closed)
            throw new SSHException("Already closed");
        int pos = buffer.wpos();
        if (bufferLength <= 0)
            // No data to send
            return;
        buffer.wpos(cmd == Constants.Message.CHANNEL_EXTENDED_DATA ? 14 : 10);
        buffer.putInt(bufferLength);
        buffer.wpos(pos);
        try {
            remoteWindow.waitAndConsume(bufferLength);
            log.debug("Send {} on channel {}", cmd, channel.getID());
            channel.getTransport().writePacket(buffer);
        } catch (SSHException e) {
            throw e;
        } catch (Exception e) {
            throw new SSHException(e);
        } finally {
            newBuffer();
        }
    }
    
    @Override
    public synchronized void write(byte[] buf, int s, int l) throws IOException
    {
        if (closed)
            throw new SSHException("Already closed");
        while (l > 0) {
            int _l = Math.min(l, remoteWindow.getPacketSize() - bufferLength);
            if (_l <= 0) {
                flush();
                continue;
            }
            buffer.putRawBytes(buf, s, _l);
            bufferLength += _l;
            s += _l;
            l -= _l;
        }
    }
    
    @Override
    public synchronized void write(int w) throws IOException
    {
        b[0] = (byte) w;
        write(b, 0, 1);
    }
    
    private void newBuffer()
    {
        buffer = new Buffer(cmd);
        buffer.putInt(channel.getRecipient());
        if (cmd == Constants.Message.CHANNEL_EXTENDED_DATA)
            buffer.putInt(1);
        buffer.putInt(0);
        bufferLength = 0;
    }
    
}
