package fi.joni.lehtinen;

import java.io.IOException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.concurrent.*;

public class Dispatcher implements Runnable {

    private final static int QUEUE_CAPACITY = 200;

    private final Selector mSelector;
    private final Object mLock = new Object();
    private final Executor mThreadPool;

    public static int getWorkerCount(){
        int prosessors = Runtime.getRuntime().availableProcessors();

        // ThreadPool(Consumers) = Prosessors - Acceptor(Producer) - Dispatcher
        int workers = prosessors - 2;

        return workers < 2 ? 2 : workers;
    }

    public Dispatcher() throws IOException {
        mSelector = Selector.open();

        int threads = getWorkerCount();

        mThreadPool = new ThreadPoolExecutor(threads, threads,
            0L, TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(QUEUE_CAPACITY),
            new ThreadPoolExecutor.CallerRunsPolicy());
    }

    public void run() {
        for (;;) {
            try {
                System.out.println("Connection Count: " + mSelector.keys().size());
                mSelector.select();
                for ( Iterator i = mSelector.selectedKeys().iterator(); i.hasNext(); ) {
                    SelectionKey selectionKey = (SelectionKey)i.next();
                    i.remove();

                    // Remove interestOps so that multiple threads don't try to handle same client
                    selectionKey.interestOps(selectionKey.interestOps() & ~selectionKey.readyOps());

                    // if queue is full task will execute in this thread
                    mThreadPool.execute( (Runnable)selectionKey.attachment() );
                }

                // Gives time for SelectableChannel.register to acquire selector's inner lock.
                synchronized (mLock) { }
            } catch (IOException x) {
                x.printStackTrace();
            }
        }
    }

    public void register( SelectableChannel selectableChannel, int ops, SessionHandler handler) throws IOException {
        synchronized (mLock) {
            // Important! This is needed for selector to release the lock that register needs.
            mSelector.wakeup();

            // register synchronizes with same object that Selector.select does and provides visibility for Dispatcher
            SelectionKey selectionKey = selectableChannel.register(mSelector, ops, handler);
            handler.setSelectionKey( selectionKey );
        }
    }

    public Selector getSelector(){
        return mSelector;
    }
}
