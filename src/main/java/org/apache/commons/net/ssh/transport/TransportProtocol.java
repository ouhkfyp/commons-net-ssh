/*
 * Licensed to the Apache Software Founation (ASF) under one
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
package org.apache.commons.net.ssh.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PublicKey;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.Config;
import org.apache.commons.net.ssh.HostKeyVerifier;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.SSHRuntimeException;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.random.Random;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Event;
import org.apache.commons.net.ssh.util.IOUtils;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link Transport} implementation.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class TransportProtocol implements Transport
{
    
    public static final int TIMEOUT = 10;
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final Config config;
    
    /** Currently active service i.e. ssh-userauth, ssh-connection */
    private Service service;
    
    private Socket socket;
    private InputStream input;
    private OutputStream output;
    
    /**
     * {@link HostKeyVerifier#verify(InetAddress, PublicKey)} is invoked by
     * {@link #verifyHost(PublicKey)} when we are ready to verify the the server's host key.
     */
    private final Queue<HostKeyVerifier> hostVerifiers = new LinkedList<HostKeyVerifier>();
    
    private boolean kexOngoing = true;
    private int sinceKeying = 1;
    
    /** For key (re)exchange */
    private final KexHandler kexer;
    
    /** Message identifier for last packet received */
    private Message cmd;
    
    private final Thread dispatcher = new Thread()
        {
            {
                setName("dispatcher");
                //setDaemon(true);
            }
            
            @Override
            public void run()
            {
                try {
                    while (!Thread.currentThread().isInterrupted())
                        converter.received((byte) input.read());
                } catch (IOException e) {
                    // We are meant to shut up and draw to a close if interrupted
                    if (!Thread.currentThread().isInterrupted())
                        die(e);
                }
                log.debug("Stopping");
            }
        };
    
    /** For encoding and decoding SSH packets */
    final Converter converter;
    
    /** Psuedo-random number generator as retrieved from the factory manager */
    final Random prng;
    
    /** Whether this session has been authenticated */
    boolean authed = false;
    
    /** Client version identification string */
    final String clientID;
    
    /** Server version identification string */
    String serverID;
    
    private final ReentrantLock lock = new ReentrantLock();
    
    private final Event<TransportException> serviceAccept = newEvent("service accept");
    
    private final Event<TransportException> close = newEvent("transport close");
    
    /**
     * 
     * @param config
     */
    public TransportProtocol(Config config)
    {
        assert config != null;
        this.config = config;
        clientID = "SSH-2.0-" + config.getVersion();
        prng = config.getRandomFactory().create();
        converter = new Converter(this);
        kexer = new KexHandler(this);
    }
    
    // Documented in interface
    public synchronized void addHostKeyVerifier(HostKeyVerifier hkv)
    {
        hostVerifiers.add(hkv);
    }
    
    // Documented in interface
    public void disconnect()
    {
        disconnect(DisconnectReason.BY_APPLICATION);
    }
    
    // Documented in interface
    public void disconnect(DisconnectReason reason)
    {
        disconnect(reason, "");
    }
    
    // Documented in interface
    public void disconnect(DisconnectReason reason, String msg)
    {
        if (msg == null)
            msg = "";
        log.debug("Sending SSH_MSG_DISCONNECT: reason=[{}], msg=[{}]", reason, msg);
        IOUtils.writeQuietly(this, new Buffer(Message.DISCONNECT) //
                                                                 .putInt(reason.toInt()) //
                                                                 .putString(msg) //
                                                                 .putString("")); // lang tag
        close();
    }
    
    public void forceRekey() throws TransportException
    {
        lock.lock();
        try {
            kexOngoing = true;
            kexer.init();
            kexer.done.await();
        } finally {
            lock.unlock();
        }
    }
    
    // Documented in interface
    public String getClientVersion()
    {
        return clientID.substring(8);
    }
    
    // Documented in interface
    public Config getConfig()
    {
        return config;
    }
    
    public InetAddress getRemoteHost()
    {
        return socket.getInetAddress();
    }
    
    public int getRemotePort()
    {
        return socket.getPort();
    }
    
    // Documented in interface
    public String getServerVersion()
    {
        return serverID == null ? serverID : serverID.substring(8);
    }
    
    // Documented in interface
    public Service getService()
    {
        lock.lock();
        try {
            return service;
        } finally {
            lock.unlock();
        }
    }
    
    // Documented in interface
    public byte[] getSessionID()
    {
        return kexer.sessionID;
    }
    
    // Documented in interface
    public void init(Socket socket) throws TransportException
    {
        try {
            this.socket = socket;
            input = socket.getInputStream();
            output = socket.getOutputStream();
            
            log.info("Client identity string: {}", clientID);
            output.write((clientID + "\r\n").getBytes());
            
            // Read server's ID
            Buffer buf = new Buffer();
            while ((serverID = readIdentification(buf)) == null)
                buf.putByte((byte) input.read());
            log.info("Server identity string: {}", serverID);
            
        } catch (IOException e) {
            throw new TransportException(e);
        }
        
        long t = System.nanoTime();
        lock.lock();
        try {
            kexer.init();
            dispatcher.start();
            kexer.done.await(TIMEOUT);
        } finally {
            lock.unlock();
        }
        log.info("Initialized in {} seconds", (System.nanoTime() - t) / 1000000000.0);
    }
    
    public boolean isRunning()
    {
        lock.lock();
        try {
            return !close.isSet() && (kexOngoing || kexer.done.isSet());
        } finally {
            lock.unlock();
        }
    }
    
    public void join(int timeout) throws TransportException
    {
        close.await(timeout);
    }
    
    public synchronized void reqService(Service service) throws TransportException
    {
        lock.lock();
        try {
            serviceAccept.clear();
            sendServiceRequest(service.getName());
            serviceAccept.await(TIMEOUT);
            setService(service);
        } finally {
            lock.unlock();
        }
    }
    
    public long sendUnimplemented() throws TransportException
    {
        // (seqi - 1) because converter always maintains the seq num applicable to the next packet
        long seq = converter.seqi - 1;
        log.info("Sending SSH_MSG_UNIMPLEMENTED for packet #{}", seq);
        return writePacket(new Buffer(Message.UNIMPLEMENTED).putInt(seq));
    }
    
    public void setAuthenticated()
    {
        synchronized (converter) {
            authed = true;
        }
    }
    
    public synchronized void setService(Service service)
    {
        lock.lock();
        try {
            if (!serviceAccept.isSet())
                throw new SSHRuntimeException("Contract violation");
            log.info("Setting active service to {}", service.getName());
            this.service = service;
        } finally {
            lock.unlock();
        }
    }
    
    public long writePacket(Buffer payload) throws TransportException
    {
        lock.lock();
        // Ensure packets sent in correct order
        try {
            if (kexOngoing) {
                // Only transport layer packets (1 to 49) allowed except SERVICE_REQUEST (5)
                int msgID = payload.array()[payload.rpos()];
                if (!(msgID >= 1 && msgID <= 49) || msgID == 5)
                    kexer.done.await(TIMEOUT);
            } else if (sinceKeying % 0x80000000L == 0) { // Rekey every 2**31 packets
                kexer.init();
                kexer.done.await(TIMEOUT);
            }
            
            long seq = converter.encode(payload);
            try {
                output.write(payload.getCompactData());
            } catch (IOException e) {
                throw new TransportException(e);
            }
            sinceKeying++;
            return seq;
        } finally {
            lock.unlock();
        }
    }
    
    private void close()
    {
        dispatcher.interrupt();
        try {
            socket.shutdownInput();
        } catch (IOException ignore) {
        }
        try {
            socket.shutdownOutput();
        } catch (IOException ignore) {
        }
        close.set();
    }
    
    @SuppressWarnings("unchecked")
    private void die(IOException ex)
    {
        
        log.error("Dying because - {}", ex.toString());
        
        SSHException causeOfDeath = SSHException.chainer.chain(ex);
        
        lock.lock();
        try {
            
            // Takes care of notifying service
            if (service != null) {
                log.debug("Notifying {}", service);
                try {
                    service.notifyError(causeOfDeath);
                } catch (Exception ignored) {
                    log.debug("Service spewed - {}", ignored.toString());
                }
                service = null;
            }
            
            // Throw the exception in any thread waiting for state change
            Event.Util.<TransportException> notifyError(causeOfDeath, kexer.done, close, serviceAccept);
            
            if (causeOfDeath.getDisconnectReason() != DisconnectReason.UNKNOWN && cmd != Message.DISCONNECT)
                /*
                 * Send SSH_MSG_DISCONNECT if we have the required info in the exception and the
                 * exception does not arise from receiving a SSH_MSG_DISCONNECT ourself
                 */
                disconnect(causeOfDeath.getDisconnectReason(), causeOfDeath.getMessage());
            else
                // stop inPump without sending disconnect message
                close();
            
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * Got an SSH_MSG_UNIMPLEMENTED, so lets see where we're at and act accordingly.
     * 
     * @param seqNum
     * @throws TransportException
     */
    private void gotUnimplemented(long seqNum) throws SSHException
    {
        lock.lock();
        try {
            if (kexOngoing)
                throw new TransportException("Received SSH_MSG_UNIMPLEMENTED while exchanging keys");
            else if (serviceAccept.isSet()) {
                if (service != null)
                    // The service might throw an exception, but that's okay and encouraged
                    service.notifyUnimplemented(seqNum);
            } else
                log.warn("Ignoring unimplemented message");
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * Reads the identification string from the SSH server. This is the very first string that is
     * sent upon connection by the server. It takes the form of, e.g. "SSH-2.0-OpenSSH_ver".
     * <p>
     * Several concerns are taken care of here, e.g. verifying protocol version, correct line
     * endings as specified in RFC and such.
     * 
     * @param buffer
     * @return
     * @throws IOException
     */
    private String readIdentification(Buffer buffer) throws IOException
    {
        String ident;
        
        byte[] data = new byte[256];
        for (;;) {
            int savedPos = buffer.rpos();
            int pos = 0;
            boolean needLF = false;
            for (;;) {
                if (buffer.available() == 0) {
                    // Need more data, so undo reading and return null
                    buffer.rpos(savedPos);
                    return null;
                }
                byte b = buffer.getByte();
                if (b == '\r') {
                    needLF = true;
                    continue;
                }
                if (b == '\n')
                    break;
                if (needLF)
                    throw new TransportException("Incorrect identification: bad line ending");
                if (pos >= data.length)
                    throw new TransportException("Incorrect identification: line too long");
                data[pos++] = b;
            }
            ident = new String(data, 0, pos);
            if (ident.startsWith("SSH-"))
                break;
            if (buffer.rpos() > 16 * 1024)
                throw new TransportException("Incorrect identification: too many header lines");
        }
        
        if (!ident.startsWith("SSH-2.0-") && !ident.startsWith("SSH-1.99-"))
            throw new TransportException(DisconnectReason.PROTOCOL_VERSION_NOT_SUPPORTED,
                                         "Server does not support SSHv2, identified as: " + ident);
        
        return ident;
    }
    
    /**
     * Sends a service request for the specified service
     * 
     * @param serviceName
     *            name of the service being requested
     * @throws TransportException
     *             if there is an error while sending the request
     */
    private void sendServiceRequest(String serviceName) throws TransportException
    {
        log.debug("Sending SSH_MSG_SERVICE_REQUEST for {}", serviceName);
        Buffer buffer = new Buffer(Message.SERVICE_REQUEST);
        buffer.putString(serviceName);
        writePacket(buffer);
    }
    
    /**
     * This is where all incoming packets are handled. If they pertain to the transport layer, they
     * are handled here; otherwise they are delegated to the active service instance if any via
     * {@link Service#handle}.
     * <p
     * Even among the transport layer specific packets, key exchange packets are delegated to
     * {@link KexHandler#handle}.
     * <p>
     * This method is called in the context of the {@link #dispatcher} thread via
     * {@link Converter#munch} when a full packet has been decoded.
     * 
     * @param packet
     *            buffer containg the packet
     * @throws SSHException
     *             if an error occurs during handling
     */
    void handle(Buffer packet) throws SSHException
    {
        cmd = packet.getCommand();
        log.debug("Received packet {}", cmd);
        int num = cmd.toInt();
        
        lock.lock();
        
        try {
            
            if (num > 49) // not a transport layer packet
                if (service != null)
                    service.handle(cmd, packet);
                else
                    sendUnimplemented();
            
            else
                switch (cmd)
                {
                    case DISCONNECT:
                        DisconnectReason code = DisconnectReason.fromInt(packet.getInt());
                        String message = packet.getString();
                        log.info("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, message);
                        throw new TransportException(code, message);
                    case IGNORE:
                        log.info("Received SSH_MSG_IGNORE");
                        break;
                    case UNIMPLEMENTED:
                        long seqNum = packet.getLong();
                        log.info("Received SSH_MSG_UNIMPLEMENTED #{}", seqNum);
                        gotUnimplemented(seqNum);
                        break;
                    case DEBUG:
                        boolean display = packet.getBoolean();
                        String msg = packet.getString();
                        log.info("Received SSH_MSG_DEBUG (display={}) '{}'", display, msg);
                        break;
                    case SERVICE_ACCEPT:
                        serviceAccept.set();
                        break;
                    case NEWKEYS:
                        if (!kexOngoing)
                            throw new TransportException(DisconnectReason.PROTOCOL_ERROR);
                        sinceKeying = 1;
                        kexOngoing = false;
                        kexer.handle(cmd, packet);
                        break;
                    case KEXINIT:
                        if (kexer.done.isSet()) { // start reexcange {
                            kexOngoing = true;
                            kexer.init();
                        }
                        kexer.handle(cmd, packet);
                        break;
                    default:
                        if (num > 29)
                            kexer.handle(cmd, packet);
                        else
                            sendUnimplemented();
                }
            
        } finally {
            lock.unlock();
        }
    }
    
    Event<TransportException> newEvent(String name)
    {
        return new Event<TransportException>(name, TransportException.chainer, lock);
    }
    
    /**
     * Tries to validate host key with all the host key verifiers known to this instance (
     * {@link #hostVerifiers})
     * 
     * @param key
     *            the host key to verify
     * @return {@code true} if host key could be verified, {@code false} if not
     */
    synchronized boolean verifyHost(PublicKey key)
    {
        for (HostKeyVerifier hkv : hostVerifiers) {
            log.debug("Trying to verify host key with {}", hkv);
            if (hkv.verify(socket.getInetAddress(), key))
                return true;
        }
        return false;
    }
    
}
