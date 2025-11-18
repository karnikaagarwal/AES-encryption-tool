package com.example.crypto;
// GCM recommended tag length (in bits)
public static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag
// GCM IV length (bytes): 12 is recommended
public static final int IV_LENGTH_BYTES = 12;


private static final SecureRandom secureRandom = new SecureRandom();


/**
* Encrypt plaintext bytes using AES-GCM with the provided key bytes.
* Returns an EncodedPayload object containing iv and ciphertext.
*/
public static EncodedPayload encrypt(byte[] keyBytes, byte[] plaintext) throws Exception {
byte[] iv = new byte[IV_LENGTH_BYTES];
secureRandom.nextBytes(iv); // random IV per encryption


SecretKey key = new SecretKeySpec(keyBytes, "AES");
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);


byte[] ciphertext = cipher.doFinal(plaintext);


return new EncodedPayload(iv, ciphertext);
}


/**
* Decrypt ciphertext using AES-GCM with the provided key and iv.
*/
public static byte[] decrypt(byte[] keyBytes, byte[] iv, byte[] ciphertext) throws Exception {
SecretKey key = new SecretKeySpec(keyBytes, "AES");
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
cipher.init(Cipher.DECRYPT_MODE, key, spec);
return cipher.doFinal(ciphertext); // will throw AEADBadTagException on tamper
}


/**
* Simple container to hold IV and ciphertext.
*/
public static class EncodedPayload {
public final byte[] iv;
public final byte[] ciphertext;


public EncodedPayload(byte[] iv, byte[] ciphertext) {
this.iv = iv;
this.ciphertext = ciphertext;
}


/**
* Return a compact base64 string containing iv + ciphertext separated.
* Format: base64(iv) + ":" + base64(ciphertext)
* This is easy to parse for this simple tool. For production, use a defined binary container.
*/
public String toBase64String() {
String ivB64 = Base64.getEncoder().encodeToString(iv);
String ctB64 = Base64.getEncoder().encodeToString(ciphertext);
return ivB64 + ":" + ctB64;
}


public static EncodedPayload fromBase64String(String s) {
String[] parts = s.split(":", 2);
if (parts.length != 2) throw new IllegalArgumentException("Invalid payload format");
byte[] iv = Base64.getDecoder().decode(parts[0]);
byte[] ct = Base64.getDecoder().decode(parts[1]);
return new EncodedPayload(iv, ct);
}
}
}
