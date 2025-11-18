package com.example.crypto;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;


/**
* Key generation helper. Two common modes supported:
* 1) Generate a random AES key (recommended for machine-to-machine use).
* 2) Derive an AES key from a password using PBKDF2 (for passphrase-based encryption).
*/
public class SecureKeyGen {
private static final SecureRandom secureRandom = new SecureRandom();


// PBKDF2 params
private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
private static final int PBKDF2_ITERATIONS = 200_000; // high iteration count
private static final int SALT_LENGTH_BYTES = 16;


/**
* Generate a random AES key of given bit length (128 or 256).
*/
public static byte[] generateRandomKey(int keySizeBits) throws Exception {
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(keySizeBits, secureRandom);
SecretKey key = kg.generateKey();
return key.getEncoded();
}


/**
* Derive AES key bytes from passphrase using PBKDF2WithHmacSHA256.
* Returns an object holding salt and derived key.
*/
public static DerivedKey deriveKeyFromPassword(char[] password, int keySizeBits) throws Exception {
byte[] salt = new byte[SALT_LENGTH_BYTES];
secureRandom.nextBytes(salt);


PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, keySizeBits);
SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
byte[] key = skf.generateSecret(spec).getEncoded();


// clear password char[] for safety (caller should also overwrite if needed)
spec.clearPassword();


return new DerivedKey(salt, key);
}


public static byte[] deriveKeyFromPasswordWithSalt(char[] password, byte[] salt, int keySizeBits) throws Exception {
PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, keySizeBits);
SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
byte[] key = skf.generateSecret(spec).getEncoded();
spec.clearPassword();
return key;
}


public static class DerivedKey {
public final byte[] salt;
public final byte[] key;
}
