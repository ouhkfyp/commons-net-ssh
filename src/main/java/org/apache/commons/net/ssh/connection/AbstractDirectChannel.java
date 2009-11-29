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

import org.apache.commons.net.ssh.SSHPacket;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Constants.Message;

/**
 * Base class for direct channels whose open is initated by the client.
 */
public abstract class AbstractDirectChannel extends AbstractChannel implements Channel.Direct
{
    
    protected AbstractDirectChannel(String name, Connection conn)
    {
        super(name, conn);
        
        /*
         * We expect to receive channel open confirmation/rejection and want to be able to handle this packet.
         */
        conn.attach(this);
    }
    
    public void open() throws ConnectionException, TransportException
    {
        trans.writePacket(buildOpenReq());
        open.await(conn.getTimeout());
    }
    
    private void gotOpenConfirmation(SSHPacket buf)
    {
        init(buf.readInt(), buf.readInt(), buf.readInt());
        open.set();
    }
    
    private void gotOpenFailure(SSHPacket buf)
    {
        open.error(new OpenFailException(getType(), buf.readInt(), buf.readString()));
        finishOff();
    }
    
    protected SSHPacket buildOpenReq()
    {
        return new SSHPacket(Message.CHANNEL_OPEN) //
                .putString(getType()) //
                .putInt(getID()) //
                .putInt(getLocalWinSize()) //
                .putInt(getLocalMaxPacketSize());
    }
    
    @Override
    protected void gotUnknown(Message cmd, SSHPacket buf) throws ConnectionException, TransportException
    {
        switch (cmd)
        {
        
        case CHANNEL_OPEN_CONFIRMATION:
            gotOpenConfirmation(buf);
            break;
        
        case CHANNEL_OPEN_FAILURE:
            gotOpenFailure(buf);
            break;
        
        default:
            super.gotUnknown(cmd, buf);
        }
    }
    
}