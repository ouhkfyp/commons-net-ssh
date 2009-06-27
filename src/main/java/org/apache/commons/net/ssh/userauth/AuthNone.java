package org.apache.commons.net.ssh.userauth;

import java.io.IOException;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

public class AuthNone extends AbstractAuthMethod
{
    
    public static final String NAME = "none";
    
    public AuthNone(Session session, Service nextService, String username)
    {
        super(session, nextService, username);
    }
    
    @Override
    protected Buffer buildRequest(Buffer buf)
    {
        return buf;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    public Result handle(Message cmd, Buffer buf) throws IOException
    {
        switch (cmd)
        {
        case SSH_MSG_USERAUTH_SUCCESS:
            return Result.SUCCESS;
        case SSH_MSG_USERAUTH_FAILURE:
            allowed = buf.getString().split(",");
            if (buf.getBoolean()) // hmm, is this meaningful for this method?
                return Result.PARTIAL_SUCCESS;
            else
                return Result.FAILURE;
        default:
            log.error("Unexpected packet");
            return Result.UNKNOWN;
        }
    }
    
}
