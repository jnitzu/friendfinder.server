package fi.joni.lehtinen;

import fi.joni.lehtinen.friendfinder.connectionprotocol.ConnectionProtocol;
import fi.joni.lehtinen.friendfinder.connectionprotocol.Reply;
import fi.joni.lehtinen.friendfinder.connectionprotocol.dto.*;

import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.ArrayList;

public class DAO {

    private static final int ITERATIONS = 10000;

    private Connection mConnection;

    public DAO(){

    }

    public void init() throws SQLException {
        mConnection = Database.instance.getConnection();
    }

    public void close() throws SQLException {
        mConnection.close();
    }

    public boolean emailTaken(Login login){
        String sql = "SELECT email FROM \"FriendFinder\".user WHERE email=?";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){
            preparedStatement.setString( 1, login.mEmail );

            ResultSet resultSet = preparedStatement.executeQuery();

            return resultSet.next();
        } catch(SQLException e){
            e.printStackTrace();
            return false;
        }

    }

    public User getUser(Login login){
        User user = null;
        String sql = "SELECT * FROM \"FriendFinder\".user WHERE email=?";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){
            preparedStatement.setString( 1, login.mEmail );

            ResultSet resultSet = preparedStatement.executeQuery();

            if(resultSet.next()){
                user = new User(
                        resultSet.getString( "email" ),
                        resultSet.getString( "firstname" ),
                        resultSet.getString( "lastname" ),
                        resultSet.getLong( "id" ),
                        resultSet.getInt( "iterations" ),
                        resultSet.getBytes( "salt" ),
                        resultSet.getBytes( "password" )
                        );
            }
        } catch(SQLException e){
            e.printStackTrace();
        }

        return user;
    }

    public int register( Register register ){
        String sql = "INSERT INTO \"FriendFinder\".user (email,firstname,lastname,iterations,salt,password) VALUES (?,?,?,?,?,?)";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            byte[] salt = Authentication.generateSalt();
            byte[] hash = Authentication.hash( register.mPassword, ITERATIONS, salt );

            preparedStatement.setString( 1, register.mEmail );
            preparedStatement.setString( 2, register.mFirstName );
            preparedStatement.setString( 3, register.mLastName );
            preparedStatement.setInt( 4, ITERATIONS );
            preparedStatement.setBytes( 5, salt );
            preparedStatement.setBytes( 6, hash );

            return preparedStatement.executeUpdate() == 1 ? 0 : -1;

        } catch(SQLException e){
            return Integer.parseInt( e.getSQLState() );
        }
    }

    public int addLocation( Location location ){
        String sql = "SELECT id FROM \"FriendFinder\".location WHERE user_id = ?";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, location.mUserID );

            ResultSet resultSet = preparedStatement.executeQuery();

            if ( resultSet.next() ){
                sql = "UPDATE \"FriendFinder\".location set user_id = ?, latitude = ?, longitude = ?, accuracy = ?, time_recorded = ? WHERE id = " + resultSet.getInt( "id" );
            } else {
                sql = "INSERT INTO \"FriendFinder\".location (user_id,latitude,longitude,accuracy,time_recorded) VALUES (?,?,?,?,?)";
            }

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }

        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, location.mUserID );
            preparedStatement.setDouble( 2, location.mLatitude );
            preparedStatement.setDouble( 3, location.mLongitude );
            preparedStatement.setDouble( 4, location.mAccuracy );
            preparedStatement.setLong( 5, location.mTimeRecorded );

            preparedStatement.executeUpdate();

            return 0;

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }
    }

    public long createCircle( Circle circle, long user_id ) {
        long group_id = -1;

        String sql = "INSERT INTO \"FriendFinder\".group (name) VALUES (?)";
        try(PreparedStatement psCircle = mConnection.prepareStatement( sql, Statement.RETURN_GENERATED_KEYS )){

            psCircle.setString( 1, circle.mName );

            psCircle.executeUpdate();

            ResultSet resultSet = psCircle.getGeneratedKeys();

            if(resultSet.next()){
                group_id = resultSet.getInt( 1 );

                sql = "INSERT INTO \"FriendFinder\".groupmembers (group_id, user_id, confirmed) VALUES (?,?,true)";

                try(PreparedStatement psCircleMember = mConnection.prepareStatement( sql )){

                    psCircleMember.setLong( 1, group_id );
                    psCircleMember.setLong( 2, user_id );

                    psCircleMember.executeUpdate();

                } catch(SQLException e){
                    e.printStackTrace();
                }
            }

        } catch(SQLException e){
            e.printStackTrace();
        }

        return group_id;
    }

    public ArrayList<Circle> getJoinRequests( long user_id ){
        String sql = "SELECT * FROM \"FriendFinder\".group WHERE \"FriendFinder\".group.id IN ( SELECT group_id FROM \"FriendFinder\".groupmembers WHERE user_id = ? AND confirmed = FALSE )";

        ArrayList<Circle> circles = new ArrayList<>();

        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, user_id );

            ResultSet resultSet = preparedStatement.executeQuery();

            while ( resultSet.next() ){
                circles.add( new Circle( resultSet.getLong( "id" ), resultSet.getString( "name" ) ) );
            }


        } catch(SQLException e){
            e.printStackTrace();
        }

        return circles;
    }

    public int confirmCircle( Circle circle, long user_id, Reply reply ){
        String sql = "UPDATE \"FriendFinder\".groupmembers set confirmed = TRUE WHERE group_id = ? AND user_id = ?";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, circle.mID );
            preparedStatement.setLong( 2, user_id );

            preparedStatement.executeUpdate();

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }

        sql = "SELECT id, firstname, lastname FROM \"FriendFinder\".user WHERE \"FriendFinder\".user.id IN ( SELECT user_id FROM \"FriendFinder\".groupmembers WHERE group_id = ? AND confirmed = TRUE AND user_id <> ? )";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, circle.mID );
            preparedStatement.setLong( 2, user_id );

            ResultSet resultSet = preparedStatement.executeQuery();

            while( resultSet.next() ){
                reply.addMessage( (resultSet.getLong( "id" ) + "," + resultSet.getString( "firstname" ) + "," + resultSet.getString( "lastname" )).getBytes( StandardCharsets.UTF_8 ));
            }

            return 0;

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }

    }

    public int declineCircle(Circle circle, long user_id){
        String sql = "DELETE FROM \"FriendFinder\".groupmembers WHERE group_id = ? AND user_id = ?";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, circle.mID );
            preparedStatement.setLong( 2, user_id );

            return preparedStatement.executeUpdate() >= 0 ? 0 : -1;

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }
    }

    public int deleteCircle( Circle circle, long user_id ){
        // CircleMembers table is made with ON DELETE CASCADE no need to delete from it
        String sql = "DELETE FROM \"FriendFinder\".group WHERE id = ? AND ( SELECT COUNT(*) FROM \"FriendFinder\".groupmembers WHERE group_id = ? AND user_id = ? ) = 1";

        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, circle.mID );
            preparedStatement.setLong( 2, circle.mID );
            preparedStatement.setLong( 3, user_id );

            preparedStatement.executeUpdate();

            return 0;

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }
    }

    public int addCircleMember( CircleMember circleMember, long user_id ){
        String sql = "SELECT COUNT(*) FROM \"FriendFinder\".groupmembers WHERE group_id = ? AND user_id = ?";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, circleMember.mGroupID );
            preparedStatement.setLong( 2, user_id );

            ResultSet resultSet = preparedStatement.executeQuery();

            if( resultSet.next() && resultSet.getInt( 1 ) != 1 ){
                return -1;
            }

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }

        long member_id = -1;

        sql = "SELECT id FROM \"FriendFinder\".user WHERE email = ?";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setString( 1, circleMember.mFriendEmail );

            ResultSet resultSet = preparedStatement.executeQuery();

            if( resultSet.next() ){
                member_id = resultSet.getLong( "id" );
            } else {
                return -2;
            }

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }


        sql = "INSERT INTO \"FriendFinder\".groupmembers (group_id, user_id) VALUES (?,?)";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, circleMember.mGroupID );
            preparedStatement.setLong( 2, member_id );

            preparedStatement.executeUpdate();

            return 0;

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }
    }

    public int removeCircleMember( CircleMember circleMember, long user_id ){

        boolean deleteCircle = false;

        String sql = "SELECT COUNT(*) FROM \"FriendFinder\".groupmembers WHERE group_id = ? AND ( SELECT COUNT(*) FROM \"FriendFinder\".groupmembers WHERE group_id = ? AND user_id = ? ) = 1";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, circleMember.mGroupID );
            preparedStatement.setLong( 2, circleMember.mGroupID );
            preparedStatement.setLong( 3, user_id );

            ResultSet resultSet = preparedStatement.executeQuery();

            if( resultSet.next() && resultSet.getInt( 1 ) == 1 ){
                sql = "DELETE FROM \"FriendFinder\".group WHERE id = ?";
                deleteCircle = true;
            } else {
                sql = "DELETE FROM \"FriendFinder\".groupmembers WHERE group_id = ? AND user_id = ? AND ( SELECT COUNT(*) FROM \"FriendFinder\".groupmembers WHERE group_id = ? AND user_id = ? ) = 1";
            }

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }

        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            if( deleteCircle ){
                preparedStatement.setLong( 1, circleMember.mGroupID );
            } else {
                preparedStatement.setLong( 1, circleMember.mGroupID );
                preparedStatement.setLong( 2, circleMember.mFriendID );
                preparedStatement.setLong( 3, circleMember.mGroupID );
                preparedStatement.setLong( 4, user_id );
            }

            preparedStatement.executeUpdate();

            return 0;

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }
    }

    public int getCircleData( long id, Reply reply ){
        StringBuilder builder = new StringBuilder();

        String sql = "SELECT * FROM \"FriendFinder\".group WHERE \"FriendFinder\".group.id IN ( SELECT group_id FROM \"FriendFinder\".groupmembers WHERE user_id = ? AND confirmed = TRUE )";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, id );

            ResultSet resultSet = preparedStatement.executeQuery();

            while( resultSet.next() ){
                builder.append( resultSet.getLong( "id" ) )
                        .append( "," )
                        .append( resultSet.getString( "name" ) )
                        .append( ";" );
            }

            // In case if empty message
            builder.append( ";" );

            reply.addMessage( builder.toString().getBytes( StandardCharsets.UTF_8 ) );
            builder = new StringBuilder();

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }

        sql = "SELECT id, group_id, user_id FROM \"FriendFinder\".groupmembers WHERE \"FriendFinder\".groupmembers.group_id IN ( SELECT group_id FROM \"FriendFinder\".groupmembers WHERE user_id = ? AND confirmed = TRUE )";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, id );

            ResultSet resultSet = preparedStatement.executeQuery();

            while( resultSet.next() ){
                builder.append( resultSet.getLong( "id" ) )
                        .append( "," )
                        .append( resultSet.getLong( "group_id" ) )
                        .append( "," )
                        .append( resultSet.getLong( "user_id" ) )
                        .append( ";" );
            }

            // In case if empty message
            builder.append( ";" );

            reply.addMessage( builder.toString().getBytes( StandardCharsets.UTF_8 ) );
            builder = new StringBuilder();

        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }


        sql = "SELECT id, firstname, lastname FROM \"FriendFinder\".user WHERE \"FriendFinder\".user.id <> ? AND \"FriendFinder\".user.id IN ( SELECT \"FriendFinder\".groupmembers.user_id FROM \"FriendFinder\".groupmembers WHERE group_id IN ( SELECT group_id FROM \"FriendFinder\".groupmembers WHERE user_id = ? AND confirmed = TRUE ) )";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, id );
            preparedStatement.setLong( 2, id );

            ResultSet resultSet = preparedStatement.executeQuery();

            while( resultSet.next() ){
                builder.append( resultSet.getLong( "id" ) )
                        .append( "," )
                        .append( resultSet.getString( "firstname" ) )
                        .append( "," )
                        .append( resultSet.getString( "lastname" ) )
                        .append( ";" );
            }

            // In case if empty message
            builder.append( ";" );

            reply.addMessage( builder.toString().getBytes( StandardCharsets.UTF_8 ) );
            builder = new StringBuilder();

            for( Circle circle : getJoinRequests(id) ){
                builder.append( circle.mID )
                        .append( "," )
                        .append( circle.mName )
                        .append( ";" );
            }

            // In case if empty message
            builder.append( ";" );

            reply.addMessage( builder.toString().getBytes( StandardCharsets.UTF_8 ) );
            builder = new StringBuilder();


        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }

        sql = "SELECT * FROM \"FriendFinder\".location WHERE \"FriendFinder\".location.user_id <> ? AND \"FriendFinder\".location.user_id IN ( SELECT \"FriendFinder\".groupmembers.user_id FROM \"FriendFinder\".groupmembers WHERE group_id IN ( SELECT group_id FROM \"FriendFinder\".groupmembers WHERE user_id = ? AND confirmed = TRUE ) )";
        try(PreparedStatement preparedStatement = mConnection.prepareStatement( sql )){

            preparedStatement.setLong( 1, id );
            preparedStatement.setLong( 2, id );

            ResultSet resultSet = preparedStatement.executeQuery();

            while( resultSet.next() ){
                builder.append( resultSet.getLong( "user_id" ) )
                        .append( "," )
                        .append( resultSet.getDouble( "latitude" ) )
                        .append( "," )
                        .append( resultSet.getDouble( "longitude" ) )
                        .append( "," )
                        .append( resultSet.getDouble( "accuracy" ) )
                        .append( "," )
                        .append( resultSet.getLong( "time_recorded" ) )
                        .append( ";" );
            }

            // In case if empty message
            builder.append( ";" );

            reply.addMessage( builder.toString().getBytes( StandardCharsets.UTF_8 ) );

            return 0;


        } catch(SQLException e){
            e.printStackTrace();
            return Integer.parseInt( e.getSQLState() );
        }
    }
}
