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
package org.apache.commons.net.ssh.sftp;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.net.ssh.util.Future;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketReader extends Thread
{
    
    /** Logger */
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final InputStream in;
    private final Map<Long, Future<Response, SFTPException>> futures = new ConcurrentHashMap<Long, Future<Response, SFTPException>>();
    
    final Packet packet = new Packet();
    private final byte[] lenBuf = new byte[4];
    
    public PacketReader(InputStream in)
    {
        this.in = in;
        setName("sftp reader");
    }
    
    private void readIntoBuffer(byte[] buf, int off, int len) throws IOException
    {
        int count = 0;
        int read = 0;
        while (count < len && ((read = in.read(buf, off + count, len - count)) != -1))
            count += read;
        if (read == -1)
            throw new SFTPException("EOF while reading packet");
    }
    
    private int getPacketLength() throws IOException
    {
        
        readIntoBuffer(lenBuf, 0, lenBuf.length);
        
        return (int) (lenBuf[0] << 24 & 0xff000000L | lenBuf[1] << 16 & 0x00ff0000L | lenBuf[2] << 8 & 0x0000ff00L | lenBuf[3] & 0x000000ffL);
    }
    
    public Packet readPacket() throws IOException
    {
        
        int len = getPacketLength();
        
        packet.rpos(0);
        packet.wpos(0);
        
        packet.ensureCapacity(len);
        
        readIntoBuffer(packet.array(), 0, len);
        
        packet.wpos(len);
        
        return packet;
    }
    
    @Override
    public void run()
    {
        try
        {
            while (true)
            {
                readPacket();
                handle();
            }
        } catch (IOException e)
        {
            for (Future<Response, SFTPException> future : futures.values())
                future.error(e);
        }
    }
    
    public void handle() throws SFTPException
    {
        Response resp = new Response(packet);
        Future<Response, SFTPException> future = futures.get(resp.getRequestID());
        log.debug("Received {} packet", resp.getType());
        if (future == null)
            throw new SFTPException("Received [" + resp.readType() + "] response for request-id " + resp.getRequestID()
                    + ", no such request was made");
        else
            future.set(resp);
    }
    
    public void expectResponseTo(Request req)
    {
        futures.put(req.readRequestID(), req.getFuture());
    }
    
}
