package fi.joni.lehtinen;

import fi.joni.lehtinen.friendfinder.connectionprotocol.*;
import fi.joni.lehtinen.friendfinder.connectionprotocol.dto.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;

public class SessionHandler implements Runnable {

    public enum State {RECEIVE,SEND}

    private SecureChannel mSecureChannel;
    private SelectionKey mSelectionKey;
    private Selector mSelector;
    private State mState = State.RECEIVE;
    private ByteBuffer mRequestBB;
    private ConnectionProtocol.Protocols mProtocol;
    private Reply mReply;
    private ByteBuffer mReplyBB;
    private boolean mIsLoggedIn = false;
    private boolean mIsChannelClosed = false;
    private long mUserID;

    public SessionHandler( SecureChannel secureChannel ) {
        mSecureChannel = secureChannel;
    }

    public void setSelectionKey( SelectionKey selectionKey ) {
        mSelectionKey = selectionKey;
    }

    @Override
    public void run() {
        try {

            switch( mState ) {
                case RECEIVE:
                    if( mIsChannelClosed || !receive() ){
                        // If channel is closed close securechannel and cancel selection key registration
                        if(mIsChannelClosed){
                            if(mSecureChannel.shutdown()){
                                mSecureChannel.close();
                                mSelectionKey.cancel();
                            } else {
                                mSelectionKey.interestOps(SelectionKey.OP_WRITE);
                            }
                        }
                        return;
                    }

                    mRequestBB.flip();

                    parse();

                    // Switch state to Send so that if Reply can't be sent this time we skip receive segment.
                    // Fall through to send
                    mState = State.SEND;

                    // Populate reply bytebuffer.
                    mReplyBB = PacketParser.getMessage( ConnectionProtocol.Protocols.REPLY, mReply );

                    for(String s : new String(mReplyBB.array(), StandardCharsets.UTF_8).split( "\n" ))
                        System.out.print(s);
                case SEND:
                    if(send()){
                        // More bytes remain to be written
                        mSelectionKey.interestOps(SelectionKey.OP_WRITE);
                    } else {
                        // Reply sent. Go back to receiving data from client
                        mState = State.RECEIVE;
                        mSelectionKey.interestOps(SelectionKey.OP_READ);
                    }

            }
        } catch( IOException | SQLException e ) {
            e.printStackTrace();
        } finally {

            // Wakeup selector everytime handler has done its job so that selector can
            // see the changes in selectionkeys' interestops'
            mSelector.wakeup();
        }

    }

    private boolean receive() throws IOException {
        if (!mSecureChannel.doHandshake(mSelectionKey)) {
            return false;
        }

        // Read and handle stream closed event
        if(mSecureChannel.read() == -1){
            mIsChannelClosed = true;
            return false;
        }

        ByteBuffer readBuffer = mSecureChannel.getReadBuffer();

        // Prepare mRequest buffer so that it can be given to ConnectionProtocol.copyReadBufferTo
        // as a parameter
        if(mRequestBB == null){
            mRequestBB = ByteBuffer.allocate( readBuffer.capacity() );
        } else if(readBuffer.position() - mRequestBB.position() > mRequestBB.remaining()){
            ByteBuffer temp = ByteBuffer.allocate( readBuffer.capacity() );
            mRequestBB.flip();
            temp.put(mRequestBB);
            mRequestBB = temp;
        }

        // Read the new bytes into requestBB and check if complete message has been read
        if ( ConnectionProtocol.copyReadBufferTo( readBuffer, mRequestBB ))
            return true;

        // Message still not received. Prepare to read again.
        mSelectionKey.interestOps(SelectionKey.OP_READ);

        return false;
    }

    private void parse() throws IllegalArgumentException, SQLException {
        mReply = new Reply();

        // Fetch mRequest content
        byte[] bytes = new byte[mRequestBB.limit()];
        mRequestBB.get( bytes );

        String request = new String( bytes, StandardCharsets.UTF_8 );
        String[] parts = request.split( ConnectionProtocol.MESSAGE_SPLIT_CHAR );

        mProtocol = ConnectionProtocol.Protocols.valueOf( parts[0] );
        Sendable sendable = PacketParser.build( mProtocol, parts );

        System.out.print( LocalDateTime.now().format( DateTimeFormatter.ISO_LOCAL_TIME ) + " => ID: " + mUserID + " | ");
        for(String s : parts)
            System.out.print(s + " | ");
        System.out.println();

        DAO dao = new DAO();
        Login login;
        User user;
        CircleMember circleMember;

        dao.init();

        switch( mProtocol ){
            case EMAIL_TAKEN:
                boolean taken = dao.emailTaken( (Login)sendable );
                mReply.mReplyCode = Reply.ReplyCode.EMAIL_TAKEN;
                mReply.addMessage( new byte[]{(byte)(taken ? 1 : 0)} );
                break;
            case LOGIN:
                login = (Login)sendable;
                user = dao.getUser( login );
                if(user == null){
                    mReply.mReplyCode = Reply.ReplyCode.CREDENTIAL_ERROR_EMAIL;
                } else if( Authentication.verify( login.mPassword, user.mIterations, user.mSalt, user.mHash )){
                    mReply.mReplyCode = Reply.ReplyCode.LOGIN_SUCCESSFUL;

                    mReply.addMessage( Utility.longToByteArray( user.mID ) );
                    mReply.addMessage( user.mFirstName.getBytes( StandardCharsets.UTF_8 ) );
                    mReply.addMessage( user.mLastName.getBytes( StandardCharsets.UTF_8 ) );
                    mReply.addMessage( user.mEmail.getBytes( StandardCharsets.UTF_8 ) );
                    mReply.addMessage( Utility.passwordEncode( user.mHash ).getBytes( StandardCharsets.UTF_8 ) );

                    mUserID = user.mID;
                    mIsLoggedIn = true;
                } else {
                    mReply.mReplyCode = Reply.ReplyCode.CREDENTIAL_ERROR_PASSWORD;
                }
                break;
            case LOGIN_HASH:
                login = (Login)sendable;
                user = dao.getUser( login );
                if(user == null){
                    mReply.mReplyCode = Reply.ReplyCode.CREDENTIAL_ERROR_EMAIL;
                } else if( Authentication.verify( login.mHash, user.mHash )){
                    mReply.mReplyCode = Reply.ReplyCode.LOGIN_SUCCESSFUL;

                    mReply.addMessage( Utility.longToByteArray( user.mID ) );
                    mReply.addMessage( user.mFirstName.getBytes( StandardCharsets.UTF_8 ) );
                    mReply.addMessage( user.mLastName.getBytes( StandardCharsets.UTF_8 ) );

                    mUserID = user.mID;
                    mIsLoggedIn = true;
                } else {
                    System.out.println(Utility.passwordEncode( login.mHash ));
                    System.out.println(Utility.passwordEncode(Utility.passwordDecode( Utility.passwordEncode( login.mHash ))));
                    System.out.println(Utility.passwordEncode( user.mHash ));
                    mReply.mReplyCode = Reply.ReplyCode.CREDENTIAL_ERROR_PASSWORD;
                }
                break;
            case REGISTER:
                Register register = (Register)sendable;
                switch( dao.register( register ) ){
                    case 0:
                        user = dao.getUser( register );

                        mReply.mReplyCode = Reply.ReplyCode.REGISTERATION_SUCCESSFUL;

                        mReply.addMessage( Utility.longToByteArray( user.mID ) );
                        mReply.addMessage( user.mFirstName.getBytes( StandardCharsets.UTF_8 ) );
                        mReply.addMessage( user.mLastName.getBytes( StandardCharsets.UTF_8 ) );
                        mReply.addMessage( user.mEmail.getBytes( StandardCharsets.UTF_8 ) );
                        mReply.addMessage( Utility.passwordEncode( user.mHash ).getBytes( StandardCharsets.UTF_8 ) );

                        mUserID = user.mID;
                        mIsLoggedIn = true;
                        break;
                    case 23505:
                        mReply.mReplyCode = Reply.ReplyCode.EMAIL_TAKEN;
                        break;
                    default:
                        mReply.mReplyCode = Reply.ReplyCode.UNKNOWN_ERROR;
                }
                break;
            case LOCATION:
                if(!mIsLoggedIn){
                    // This should not happen, but in case it does
                    mReply.mReplyCode = Reply.ReplyCode.NOT_LOGGED_IN;
                } else {
                    Location location = (Location)sendable;

                    if(location.mUserID != mUserID){
                        mReply.mReplyCode = Reply.ReplyCode.WRONG_USER_ID;
                        break;
                    }

                    switch( dao.addLocation( location ) ){
                        case 0:
                            mReply.mReplyCode = Reply.ReplyCode.LOCATION_TRANSFER_SUCCESS;
                            break;
                        default:
                            mReply.mReplyCode = Reply.ReplyCode.UNKNOWN_ERROR;

                    }
                }

                break;
            case CREATE_CIRCLE:
                if(!mIsLoggedIn){
                    // This should not happen, but in case it does
                    mReply.mReplyCode = Reply.ReplyCode.NOT_LOGGED_IN;
                } else {
                    long group_id = dao.createCircle( (Circle)sendable, mUserID );
                    if( group_id != -1 ) {
                        mReply.mReplyCode = Reply.ReplyCode.CIRCLE_CREATE_SUCCESSFUL;
                        mReply.addMessage( Utility.longToByteArray( group_id ) );
                    } else {
                        mReply.mReplyCode = Reply.ReplyCode.UNKNOWN_ERROR;
                    }
                }
                break;
            case JOIN_REQUESTS:
                if(!mIsLoggedIn){
                    // This should not happen, but in case it does
                    mReply.mReplyCode = Reply.ReplyCode.NOT_LOGGED_IN;
                } else {
                    mReply.mReplyCode = Reply.ReplyCode.JOIN_REQUEST_SUCCESSFUL;
                    ArrayList<Circle> circles = dao.getJoinRequests( mUserID );

                    for(Circle circle : circles)
                        mReply.addMessage( (circle.mID + "," + circle.mName).getBytes( StandardCharsets.UTF_8 ) );
                }
                break;
            case CONFIRM_JOIN_REQUEST:
                switch( dao.confirmCircle( (Circle)sendable, mUserID, mReply ) ){
                    case 0:
                        mReply.mReplyCode = Reply.ReplyCode.JOIN_REQUEST_CONFIRMED_SUCCESSFULLY;
                        break;
                    default:
                        mReply.mReplyCode = Reply.ReplyCode.JOIN_REQUEST_ERROR;
                }
                break;
            case DECLINE_JOIN_REQUEST:
                switch( dao.declineCircle( (Circle)sendable, mUserID ) ){
                    case 0:
                        mReply.mReplyCode = Reply.ReplyCode.JOIN_REQUEST_DECLINED_SUCCESSFULLY;
                        break;
                    default:
                        mReply.mReplyCode = Reply.ReplyCode.JOIN_REQUEST_ERROR;
                }
                break;
            case ADD_CIRCLE_MEMBER:
                switch( dao.addCircleMember( (CircleMember)sendable, mUserID ) ){
                    case 0:
                        mReply.mReplyCode = Reply.ReplyCode.ADD_FRIEND_SUCCESSFUL;
                        break;
                    case -1:
                        mReply.mReplyCode = Reply.ReplyCode.NOT_PART_OF_CIRCLE;
                        break;
                    case -2:
                        mReply.mReplyCode = Reply.ReplyCode.FRIEND_NOT_FOUND;
                        break;
                    default:
                        mReply.mReplyCode = Reply.ReplyCode.UNKNOWN_ERROR;
                }
                break;
            case REMOVE_CIRCLE_MEMBER:
                circleMember = (CircleMember)sendable;
                switch( dao.removeCircleMember( circleMember, mUserID ) ){
                    case 0:
                        mReply.mReplyCode = Reply.ReplyCode.REMOVE_FRIEND_SUCCESSFUL;
                        break;
                    default:
                        mReply.mReplyCode = Reply.ReplyCode.UNKNOWN_ERROR;
                }
                break;
            case DELETE_CIRCLE:
                switch( dao.deleteCircle( (Circle)sendable, mUserID ) ){
                    case 0:
                        mReply.mReplyCode = Reply.ReplyCode.CIRCLE_DELETE_SUCCESSFUL;
                        break;
                    default:
                        mReply.mReplyCode = Reply.ReplyCode.UNKNOWN_ERROR;
                }
                break;
            case CIRCLE_DATA:
                switch( dao.getCircleData( mUserID, mReply ) ){
                    case 0:
                        mReply.mReplyCode = Reply.ReplyCode.DATA_REQUEST_SUCCESSFUL;
                        break;
                    default:
                        mReply.mReplyCode = Reply.ReplyCode.DATA_REQUEST_ERROR;
                }
                break;
            default:
                mReply.mReplyCode = Reply.ReplyCode.UNKNOWN_REQUEST_FORMAT;
        }

        // Release connection back to connection pool
        dao.close();

        // Clear the request buffer. So it can handle next request
        mRequestBB.clear();

    }

    private boolean send() throws IOException {
        if(mReplyBB.hasRemaining()){
            mSecureChannel.write( mReplyBB );
        }

        return mReplyBB.hasRemaining() || !mSecureChannel.flush();
    }

    public void setSelector(Dispatcher dispatcher){
        mSelector = dispatcher.getSelector();
    }
}
