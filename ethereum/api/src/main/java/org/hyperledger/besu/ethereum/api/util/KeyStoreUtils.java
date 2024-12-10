/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.api.util;

import org.hyperledger.besu.crypto.SecureRandomProvider;
import org.hyperledger.besu.datatypes.Hash;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Locale;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.tuweni.bytes.Bytes;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.utils.Numeric;

/**
 * Utility class for managing Ethereum account keystores. Provides functionality to generate and
 * store encrypted private keys.
 */
public class KeyStoreUtils {
  private static final String KEYSTORE_DIRECTORY =
      System.getProperty("user.home") + "/.besu/data/keystore";
  private static final String ENCRYPTION_ALGORITHM = "AES/CTR/NoPadding";
  private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final int KEY_LENGTH = 256;
  private static final int ITERATIONS = 65536;
  private static final int SALT_LENGTH = 16;
  private static final SecureRandom SECURE_RANDOM = SecureRandomProvider.createSecureRandom();

  /**
   * Generates a new random private key.
   *
   * @return A string representation of the generated private key
   */
  public static String generatePrivateKey() {
    byte[] privateKeyBytes = new byte[32];
    SECURE_RANDOM.nextBytes(privateKeyBytes);
    // Ensure we have a valid private key for secp256k1
    BigInteger privKey = new BigInteger(1, privateKeyBytes);
    BigInteger secp256k1n =
        new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    while (privKey.compareTo(BigInteger.ZERO) <= 0 || privKey.compareTo(secp256k1n) >= 0) {
      SECURE_RANDOM.nextBytes(privateKeyBytes);
      privKey = new BigInteger(1, privateKeyBytes);
    }
    String generatedKey = Numeric.toHexStringNoPrefix(privateKeyBytes);
    System.out.println("Debug - generatePrivateKey: " + generatedKey);
    return generatedKey;
  }

  /**
   * Saves a private key to an encrypted keystore file.
   *
   * @param privateKey The private key to encrypt and store
   * @param password The password to use for encryption
   * @param name The name identifier for the account
   * @return The path to the created keystore file
   * @throws RuntimeException if the keystore file cannot be created or written
   */
  public static String savePrivateKeyToFile(
      final String privateKey, final String password, final String name) {
    try {
      // Ensure private key is properly formatted
      String cleanPrivateKey = privateKey.startsWith("0x") ? privateKey.substring(2) : privateKey;
      if (cleanPrivateKey.length() != 64) {
        throw new IllegalArgumentException("Invalid private key length");
      }

      System.out.println("Debug - savePrivateKeyToFile privateKey: " + cleanPrivateKey);
      // Generate the address from the private key
      byte[] privateKeyBytes = Numeric.hexStringToByteArray(cleanPrivateKey);
      ECKeyPair keyPair = ECKeyPair.create(privateKeyBytes);
      String addressNoPrefix = Keys.getAddress(keyPair);
      System.out.println("Debug - savePrivateKeyToFile address: " + addressNoPrefix);

      // Create the keystore directory if it doesn't exist
      Path keystoreDir = Paths.get(KEYSTORE_DIRECTORY);
      Files.createDirectories(keystoreDir);

      // Generate a unique file name for the keystore file
      String fileName =
          String.format(
              "keystore-%s-%d.json",
              name.toLowerCase(Locale.ROOT).replaceAll("\\s+", "-"), System.currentTimeMillis());
      Path filePath = keystoreDir.resolve(fileName);

      // Generate a random salt
      byte[] salt = new byte[SALT_LENGTH];
      SECURE_RANDOM.nextBytes(salt);

      // Generate random IV
      byte[] iv = new byte[16];
      SECURE_RANDOM.nextBytes(iv);

      // Derive the encryption key from the password and salt
      SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
      KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
      SecretKey secretKey = factory.generateSecret(spec);
      byte[] derivedKey = secretKey.getEncoded();
      // Use first 16 bytes for encryption key
      byte[] encryptionKey = new byte[16];
      System.arraycopy(derivedKey, 0, encryptionKey, 0, 16);
      SecretKeySpec key = new SecretKeySpec(encryptionKey, "AES");

      // Encrypt the private key
      Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
      byte[] encryptedPrivateKey = cipher.doFinal(privateKeyBytes);

      // Create Web3 Secret Storage (V3) format
      String keystoreContent =
          String.format(
              "{"
                  + "\"version\":3,"
                  + "\"id\":\"%s\","
                  + "\"address\":\"%s\","
                  + "\"crypto\":{"
                  + "\"ciphertext\":\"%s\","
                  + "\"cipherparams\":{\"iv\":\"%s\"},"
                  + "\"cipher\":\"aes-128-ctr\","
                  + "\"kdf\":\"pbkdf2\","
                  + "\"kdfparams\":{"
                  + "\"dklen\":32,"
                  + "\"salt\":\"%s\","
                  + "\"c\":%d,"
                  + "\"prf\":\"hmac-sha256\""
                  + "},"
                  + "\"mac\":\"%s\""
                  + "}"
                  + "}",
              UUID.randomUUID(),
              addressNoPrefix,
              Numeric.toHexString(encryptedPrivateKey).substring(2),
              Numeric.toHexString(iv).substring(2),
              Numeric.toHexString(salt).substring(2),
              ITERATIONS,
              calculateMac(derivedKey, encryptedPrivateKey));

      // Save the keystore file
      Files.write(filePath, keystoreContent.getBytes(StandardCharsets.UTF_8));

      return filePath.toString();
    } catch (Exception e) {
      throw new RuntimeException("Failed to save keystore file", e);
    }
  }

  private static String calculateMac(final byte[] derivedKey, final byte[] cipherText) {
    // Concatenate the last 16 bytes of the derived key with the ciphertext
    byte[] macBody =
        Bytes.concatenate(Bytes.wrap(derivedKey).slice(16, 16), Bytes.wrap(cipherText)).toArray();
    return Hash.hash(Bytes.wrap(macBody)).toHexString().substring(2);
  }

  /**
   * Gets the Ethereum address for a private key.
   *
   * @param privateKey The private key in hex format
   * @return The Ethereum address with checksum
   */
  public static String getAddress(final String privateKey) {
    String cleanPrivateKey = privateKey.startsWith("0x") ? privateKey.substring(2) : privateKey;
    System.out.println("Debug - getAddress privateKey: " + cleanPrivateKey);
    byte[] privateKeyBytes = Numeric.hexStringToByteArray(cleanPrivateKey);
    ECKeyPair keyPair = ECKeyPair.create(privateKeyBytes);
    String addressNoPrefix = Keys.getAddress(keyPair);
    System.out.println("Debug - getAddress address: " + addressNoPrefix);
    return Keys.toChecksumAddress("0x" + addressNoPrefix);
  }
}
