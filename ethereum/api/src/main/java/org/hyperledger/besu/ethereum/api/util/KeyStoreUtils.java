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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.tuweni.bytes.Bytes32;

/**
 * Utility class for managing Ethereum account keystores. Provides functionality to generate and
 * store encrypted private keys.
 */
public class KeyStoreUtils {
  private static final String KEYSTORE_DIRECTORY =
      System.getProperty("user.home") + "/.besu/data/keystore";
  private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
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
    return Bytes32.wrap(privateKeyBytes).toString();
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
      String keystoreContent =
          String.format(
              "{\"name\":\"%s\",\"privateKey\":\"%s\",\"iv\":\"%s\",\"salt\":\"%s\"}",
              name, encodedPrivateKey, encodedIV, encodedSalt);

      // Save the keystore file
      Files.write(filePath, keystoreContent.getBytes(StandardCharsets.UTF_8));

      return filePath.toString();
    } catch (Exception e) {
      // Handle the exception
      throw new RuntimeException("Failed to save keystore file", e);
    }
  }
}
