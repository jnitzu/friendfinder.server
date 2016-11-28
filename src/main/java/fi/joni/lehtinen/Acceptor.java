package fi.joni.lehtinen;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Acceptor implements Runnable {

    private ServerSocketChannel mServerSocketChannel;
    private SSLContext mSSLContext;
    private Dispatcher mDispatcher;

    public Acceptor( ServerSocketChannel serverSocketChannel, SSLContext SSLContext, Dispatcher dispatcher ) {
        mServerSocketChannel = serverSocketChannel;
        mSSLContext = SSLContext;
        mDispatcher = dispatcher;
    }

    public void run() {
        for (;;) {
            try {
                SocketChannel socketChannel = mServerSocketChannel.accept();
                SecureChannel secureChannel = new SecureChannel( socketChannel, mSSLContext );

                SessionHandler sessionHandler = new SessionHandler(secureChannel);

                // Add Dispatcher's selector to secure channel so that Dispatcher
                // can be woken up when selectionkey interestops are changed
                sessionHandler.setSelector( mDispatcher );

                System.out.println( LocalDateTime.now().format( DateTimeFormatter.ISO_LOCAL_TIME ) + " => Connection accepted: " + socketChannel.getRemoteAddress());

                mDispatcher.register(socketChannel, SelectionKey.OP_READ, sessionHandler);

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
