package examples.ssh;

import java.io.IOException;
import java.io.OutputStream;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.Session;
import org.apache.commons.net.ssh.connection.Session.Shell;
import org.apache.commons.net.ssh.util.IOUtils;

class PTY
{
    
    public static void main(String... args) throws IOException
    {
        SSHClient client = new SSHClient();
        client.initUserKnownHosts();
        client.connect("localhost");
        Session session = null;
        try {
            client.authPublickey("shikhar");
            session = client.startSession();
            session.allocateDefaultPTY();
            Shell shell = session.startShell();
            IOUtils.pipe(shell.getInputStream(), System.out, 1, null);
            IOUtils.pipe(shell.getErrorStream(), System.out, 1, null);
            OutputStream os = shell.getOutputStream();
            int i;
            while ((i = System.in.read()) != -1) {
                os.write(i);
                os.flush();
            }
            os.close();
        } finally {
            if (session != null)
                session.close();
            client.disconnect();
        }
    }
    
}
