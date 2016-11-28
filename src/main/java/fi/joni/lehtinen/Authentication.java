package fi.joni.lehtinen;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

public class Authentication {

    private static final int PASSWORD_BIT_LENGTH = 256;

    public static byte[] hash( String password, int iterations, byte[] salt ) {

        PBEKeySpec spec = new PBEKeySpec( password.toCharArray(), salt, iterations, PASSWORD_BIT_LENGTH );
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA256" );
            return skf.generateSecret( spec ).getEncoded();
        } catch( NoSuchAlgorithmException | InvalidKeySpecException e ) {
            e.printStackTrace();
        } finally {
            spec.clearPassword();
        }

        return null;
    }

    public static boolean verify( String password, int iterations, byte[] salt, byte[] correct_pw_hash ) {
        byte[] hashed_password = hash( password, iterations, salt );

        if( hashed_password == null ) {
            return false;
        }

        for( int i = 0; i < correct_pw_hash.length; i++ ) {
            if( correct_pw_hash[ i ] != hashed_password[ i ] )
                return false;
        }

        return true;
    }

    public static boolean verify( byte[] password, byte[] correct_pw_hash ) {
        return Arrays.equals(password, correct_pw_hash);
    }

    public static byte[] generateSalt() {
        Random random = new SecureRandom();
        byte[] salt = new byte[ 16 ];
        random.nextBytes( salt );
        return salt;
    }
}