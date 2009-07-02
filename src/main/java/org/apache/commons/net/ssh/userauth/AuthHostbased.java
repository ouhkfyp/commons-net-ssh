//package org.apache.commons.net.ssh.userauth;
//
//import org.apache.commons.net.ssh.Service;
//import org.apache.commons.net.ssh.Constants.Message;
//import org.apache.commons.net.ssh.keys.KeyPair;
//import org.apache.commons.net.ssh.transport.Session;
//import org.apache.commons.net.ssh.util.Buffer;
//
//public class AuthHostbased extends KeyedAuthMethod
//{
//    
//    private final String FQDN;
//    
//    public static final String NAME = "hostbased";
//    
//    public AuthHostbased(Session session, Service nextService, String username, KeyPair kp,
//            String FQDN)
//    {
//        super(session, nextService, username, kp);
//        this.FQDN = FQDN;
//    }
//    
//    @Override
//    protected Buffer buildRequest()
//    {
//        Buffer buf = buildRequestCommon(new Buffer(Message.USERAUTH_REQUEST));
//        putPubKey(buf);
//        buf.putString(FQDN);
//        buf.putString(username);
//        
//        return buf;
//    }
//    
//    public String getName()
//    {
//        return NAME;
//    }
//    
//}
