package fi.joni.lehtinen;

import org.apache.commons.dbcp2.BasicDataSource;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

public class Database {

    public static final Database instance = new Database();
    private final int INITIAL_SIZE;

    private final BasicDataSource mBasicDataSource;

    private Database(){
        mBasicDataSource = new BasicDataSource();

        // Worker threads + Dispatcher
        INITIAL_SIZE = Dispatcher.getWorkerCount() + 1;

        String propFileName = "build/resources/main/database.properties";
        try(InputStream inputStream = new FileInputStream(propFileName)) {
            Properties properties = new Properties();

            if (inputStream != null) {
                properties.load(inputStream);
            } else {
                throw new FileNotFoundException("property file '" + propFileName + "' not found!");
            }

            mBasicDataSource.setUsername( properties.getProperty("username") );
            mBasicDataSource.setPassword( properties.getProperty("password") );
            mBasicDataSource.setUrl( properties.getProperty("url") );
            mBasicDataSource.setDriverClassName( properties.getProperty("driverClassName") );
            mBasicDataSource.setInitialSize( INITIAL_SIZE );
            mBasicDataSource.setMaxTotal( INITIAL_SIZE );

        } catch (Exception e) {
            e.printStackTrace();
            System.exit( 0 );
        }
    }

    public Connection getConnection() throws SQLException{
        return mBasicDataSource.getConnection();
    }
}
