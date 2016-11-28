package fi.joni.lehtinen;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.*;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

public class SecureChannel {

    private static final ByteBuffer EMPTY_BB = ByteBuffer.allocate(0);

    private SocketChannel mSocketChannel;
    private SSLEngine mSSLEngine = null;

    private ByteBuffer mInAppBB;

    private ByteBuffer mInNetBB;
    private ByteBuffer mOutNetBB;

    private int mAppBBSize;
    private int mNetBBSize;

    private SSLEngineResult.HandshakeStatus mInitialHSStatus;
    private boolean mInitialHSComplete;
    private boolean mShutdown = false;

    SecureChannel( SocketChannel socketChannel, SSLContext sslContext) throws IOException {
        mSocketChannel = socketChannel;
        mSocketChannel.configureBlocking( false );

        mSSLEngine = sslContext.createSSLEngine();
        mSSLEngine.setUseClientMode(false);
        mInitialHSStatus = HandshakeStatus.NEED_UNWRAP;
        mInitialHSComplete = false;


        mAppBBSize = mSSLEngine.getSession().getApplicationBufferSize();
        mNetBBSize = mSSLEngine.getSession().getPacketBufferSize();

        mInAppBB = ByteBuffer.allocate( mAppBBSize );
        mInNetBB = ByteBuffer.allocate( mNetBBSize );
        mOutNetBB = ByteBuffer.allocate( mNetBBSize );

        mOutNetBB.position(0);
        mOutNetBB.limit(0);
    }

    private boolean tryFlush(ByteBuffer source) throws IOException {
        mSocketChannel.write(source);
        return !source.hasRemaining();
    }

    private void resizeRequestBB() {
        if (mInAppBB.remaining() < mAppBBSize ) {
            // Expand buffer for large request
            ByteBuffer bb = ByteBuffer.allocate(mInAppBB.capacity() * 2);
            mInAppBB.flip();
            bb.put(mInAppBB);
            mInAppBB = bb;
        }
    }

    /*
     * Adjust the inbount network buffer to an appropriate size.
     */
    private void resizeResponseBB() {
        ByteBuffer bb = ByteBuffer.allocate( mNetBBSize );
        mInNetBB.flip();
        bb.put(mInNetBB);
        mInNetBB = bb;
    }

    ByteBuffer getReadBuffer(){
        return mInAppBB;
    }

    boolean doHandshake(SelectionKey selectionKey) throws IOException {

        SSLEngineResult result;

        if (mInitialHSComplete) {
            return mInitialHSComplete;
        }

        // Flush outgoing buffer. Message wrap happened earlier execution of
        // this method in different thread
        if (mOutNetBB.hasRemaining()) {

            if (!tryFlush(mOutNetBB)) {
                // If flush was unsuccessful register for write
                selectionKey.interestOps(SelectionKey.OP_WRITE);
                return false;
            }

            // If flush was successful check if handshaking is done and raise
            // flag for which interestops we should be checking for
            switch (mInitialHSStatus) {

                case FINISHED:
                    mInitialHSComplete = true;
                    // Fall-through to reregister need for a Read.

                case NEED_UNWRAP:
                    selectionKey.interestOps(SelectionKey.OP_READ);
                    break;
                case NEED_WRAP:
                    selectionKey.interestOps(SelectionKey.OP_WRITE);
                    break;
                // NOT_HANDSHAKING or NEED_TASK can't happen here
            }

            return mInitialHSComplete;
        }

        // Outgoing buffer is empty
        switch (mInitialHSStatus) {

            case NEED_UNWRAP:
                if (mSocketChannel.read(mInNetBB) == -1) {
                    mSSLEngine.closeInbound();
                    return mInitialHSComplete;
                }

                needIO:
                while (mInitialHSStatus == HandshakeStatus.NEED_UNWRAP) {
                    resizeRequestBB();    // expected room for unwrap
                    mInNetBB.flip();
                    result = mSSLEngine.unwrap(mInNetBB, mInAppBB);
                    mInNetBB.compact();

                    mInitialHSStatus = result.getHandshakeStatus();

                    switch (result.getStatus()) {

                        case OK:
                            switch (mInitialHSStatus) {
                                case NOT_HANDSHAKING:
                                    throw new IOException(
                                            "Not handshaking during initial handshake");

                                case NEED_TASK:
                                    mInitialHSStatus = doSLLEngineTasks();
                                    break;

                                case FINISHED:
                                    mInitialHSComplete = true;
                                    break needIO;
                            }

                            break;

                        case BUFFER_UNDERFLOW:
                            // Resize buffer if needed.
                            mNetBBSize = mSSLEngine.getSession().getPacketBufferSize();
                            if ( mNetBBSize > mInNetBB.capacity()) {
                                resizeResponseBB();
                            }

                            break needIO;

                        case BUFFER_OVERFLOW:
                            // Reset the application buffer size.
                            mAppBBSize = mSSLEngine.getSession().getApplicationBufferSize();
                            break;

                        default: //CLOSED:
                            throw new IOException("Received" + result.getStatus() +
                                    "during initial handshaking");
                    }
                }  // "needIO" block.

                // Check if we still need to read otherwise transition to write
                if (mInitialHSStatus != HandshakeStatus.NEED_WRAP) {
                    selectionKey.interestOps(SelectionKey.OP_READ);
                    break;
                }

                // Fall through and fill the write buffers.

            case NEED_WRAP:
                // We flush the buffer above so we can clear outgoing buffer
                mOutNetBB.clear();
                result = mSSLEngine.wrap(EMPTY_BB, mOutNetBB);
                mOutNetBB.flip();

                mInitialHSStatus = result.getHandshakeStatus();

                switch (result.getStatus()) {
                    case OK:

                        if (mInitialHSStatus == HandshakeStatus.NEED_TASK) {
                            mInitialHSStatus = doSLLEngineTasks();
                        }

                        selectionKey.interestOps(SelectionKey.OP_WRITE);

                        break;

                    default: // BUFFER_OVERFLOW/BUFFER_UNDERFLOW/CLOSED:
                        throw new IOException("Received" + result.getStatus() + "during initial handshaking");
                }
                break;

            default: // NOT_HANDSHAKING/NEED_TASK/FINISHED
                throw new RuntimeException("Invalid Handshaking State " + mInitialHSStatus);
        }

        return mInitialHSComplete;
    }

    int read() throws IOException {
        SSLEngineResult result;

        if (!mInitialHSComplete) {
            throw new IllegalStateException();
        }

        int pos = mInAppBB.position();

        if (mSocketChannel.read(mInNetBB) == -1) {
            try{
                mSSLEngine.closeInbound();
            } catch( SSLException e ){
                e.printStackTrace();
            }
            return -1;
        }

        do {
            resizeRequestBB();
            mInNetBB.flip();
            result = mSSLEngine.unwrap(mInNetBB, mInAppBB);
            mInNetBB.compact();

            switch (result.getStatus()) {

                case BUFFER_OVERFLOW:
                    // Reset the application buffer size.
                    mAppBBSize = mSSLEngine.getSession().getApplicationBufferSize();
                    break;

                case BUFFER_UNDERFLOW:
                    // Resize buffer if needed.
                    mNetBBSize = mSSLEngine.getSession().getPacketBufferSize();
                    if ( mNetBBSize > mInNetBB.capacity()) {
                        resizeResponseBB();

                        break; // break, next read will support larger buffer.
                    }
                case OK:
                    if (result.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
                        doSLLEngineTasks();
                    }
                    break;
                case CLOSED:
                    return -1;
            }
        } while ((mInNetBB.position() != 0) && result.getStatus() != Status.BUFFER_UNDERFLOW);

        return (mInAppBB.position() - pos);
    }

    int write(ByteBuffer outAppBB) throws IOException {

        if (!mInitialHSComplete) {
            throw new IllegalStateException();
        }

        int retValue = 0;

        if (mOutNetBB.hasRemaining() && !tryFlush(mOutNetBB)) {
            return retValue;
        }

        mOutNetBB.clear();

        SSLEngineResult result = mSSLEngine.wrap(outAppBB, mOutNetBB);
        retValue = result.bytesConsumed();

        mOutNetBB.flip();

        switch (result.getStatus()) {

            case OK:
                if (result.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
                    doSLLEngineTasks();
                }
                break;

            default:
                throw new IOException("sslEngine error during data write: " + result.getStatus());
        }

        if (mOutNetBB.hasRemaining()) {
            tryFlush(mOutNetBB);
        }

        return retValue;

    }

    boolean flush() throws IOException{
        if (mOutNetBB.hasRemaining()) {
            tryFlush(mOutNetBB);
        }

        return !mOutNetBB.hasRemaining();
    }

    private SSLEngineResult.HandshakeStatus doSLLEngineTasks() {

        Runnable runnable;

        while ((runnable = mSSLEngine.getDelegatedTask()) != null) {
            runnable.run();
        }
        return mSSLEngine.getHandshakeStatus();
    }

    boolean shutdown() throws IOException {

        if (!mShutdown) {
            mSSLEngine.closeOutbound();
            mShutdown = true;
        }

        if (mOutNetBB.hasRemaining() && tryFlush(mOutNetBB)) {
            return false;
        }

        /*
         * By RFC 2616, we can "fire and forget" our close_notify
         * message, so that's what we'll do here.
         */
        mOutNetBB.clear();
        SSLEngineResult result = mSSLEngine.wrap(EMPTY_BB, mOutNetBB);
        if ( result.getStatus() != Status.CLOSED ) {
            throw new SSLException("Improper close state");
        }
        mOutNetBB.flip();

        if (mOutNetBB.hasRemaining()) {
            tryFlush(mOutNetBB);
        }

        return ( !mOutNetBB.hasRemaining() && (result.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_WRAP ));
    }

    void close() throws IOException {
        mSocketChannel.close();
    }
}
