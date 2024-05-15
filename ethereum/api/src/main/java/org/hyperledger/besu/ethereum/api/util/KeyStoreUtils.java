package org.hyperledger.besu.ethereum.api.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.tuweni.bytes.Bytes32;

public class KeyStoreUtils {
  private static final String KEYSTORE_DIRECTORY = System.getProperty("user.home") + "/.besu/data/keystore";
  private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final int KEY_LENGTH = 256;
  private static final int ITERATIONS = 65536;
  private static final int SALT_LENGTH = 16;

  public static String generatePrivateKey() {
    SecureRandom random = new SecureRandom();
    byte[] privateKeyBytes = new byte[32];
    random.nextBytes(privateKeyBytes);
    return Bytes32.wrap(privateKeyBytes).toString();
  }

  public static String savePrivateKeyToFile(String privateKey, String password) {
    try {
      // Create the keystore directory if it doesn't exist
      Path keystoreDir = Paths.get(KEYSTORE_DIRECTORY);
      Files.createDirectories(keystoreDir);

      // Generate a unique file name for the keystore file
      String fileName = "keystore-" + System.currentTimeMillis() + ".json";
      Path filePath = keystoreDir.resolve(fileName);

      // Generate a random salt
      SecureRandom random = new SecureRandom();
      byte[] salt = new byte[SALT_LENGTH];
      random.nextBytes(salt);

      // Derive the encryption key from the password and salt
      SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
      KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
      SecretKey secretKey = factory.generateSecret(spec);
      SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), "AES");

      // Encrypt the private key
      Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] iv = cipher.getIV();
      byte[] encryptedPrivateKey = cipher.doFinal(privateKey.getBytes(StandardCharsets.UTF_8));

      // Encode the encrypted private key, IV, and salt as Base64
      String encodedPrivateKey = Base64.getEncoder().encodeToString(encryptedPrivateKey);
      String encodedIV = Base64.getEncoder().encodeToString(iv);
      String encodedSalt = Base64.getEncoder().encodeToString(salt);

      // Create the keystore file content
      String keystoreContent = String.format("{\"privateKey\":\"%s\",\"iv\":\"%s\",\"salt\":\"%s\"}", encodedPrivateKey, encodedIV, encodedSalt);

      // Save the keystore file
      Files.write(filePath, keystoreContent.getBytes(StandardCharsets.UTF_8));

      return filePath.toString();
    } catch (Exception e) {
      // Handle the exception 
      throw new RuntimeException("Failed to save keystore file", e);
    }
  }
}