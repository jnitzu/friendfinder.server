package fi.joni.lehtinen;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.channels.ServerSocketChannel;
import java.security.*;
import java.security.cert.CertificateException;

public class Server {

    private ServerSocketChannel mServerSocketChannel;
    private SSLContext mSSLContext;


    public Server(){
        this(8000,1024);
    }

    public Server( int port, int backlog ){

        createSSLContext();

        try{
            mServerSocketChannel = ServerSocketChannel.open();
            mServerSocketChannel.setOption( StandardSocketOptions.SO_REUSEADDR, true );
            mServerSocketChannel.bind(new InetSocketAddress(port), backlog);
        } catch( IOException e ){
            e.printStackTrace();
        }
    }

    private void createSSLContext() {
        try {
            char[] keyStorePassphrase = "removed".toCharArray();
            KeyStore ksKeys = KeyStore.getInstance( "JKS" );
            ksKeys.load( new FileInputStream( "build/resources/main/ServerKeystore.jks" ), keyStorePassphrase );

            // KeyManager decides which key material to use.
            KeyManagerFactory kmf = KeyManagerFactory.getInstance( "SunX509" );
            kmf.init( ksKeys, keyStorePassphrase );

            // Trust store contains certificates of trusted certificate authorities.
            // We'll need this to do client authentication.
            char[] trustStorePassphrase = "removed".toCharArray();
            KeyStore ksTrust = KeyStore.getInstance( "JKS" );
            ksTrust.load( new FileInputStream( "build/resources/main/ServerTruststore.jks" ), trustStorePassphrase );

            // TrustManager decides which certificate authorities to use.
            TrustManagerFactory tmf = TrustManagerFactory.getInstance( "SunX509" );
            tmf.init( ksTrust );

            mSSLContext = SSLContext.getInstance( "TLS" );
            mSSLContext.init( kmf.getKeyManagers(), tmf.getTrustManagers(), null );

        } catch( KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyManagementException | IOException e ) {
            e.printStackTrace();
        }
    }

    public static void main( String[] args ) {

        Server server = new Server();
        Dispatcher dispatcher = null;

        try {
            dispatcher = new Dispatcher();
        } catch( IOException e ) {
            e.printStackTrace();
            System.exit( 0 );
        }

        Acceptor acceptor = new Acceptor( server.mServerSocketChannel, server.mSSLContext, dispatcher );

        new Thread( dispatcher ).start();
        new Thread( acceptor ).start();

    }

}
