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
package org.hyperledger.besu.cli.subcommands;

import org.hyperledger.besu.ethereum.api.util.KeyStoreUtils;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Command to create a new Ethereum account. Creates a new private key and stores it in an encrypted
 * keystore file.
 */
@Command(
    name = "create-account",
    description = "Creates a new account and stores the private key in a keystore file",
    mixinStandardHelpOptions = true)
public class CreateAccountCommand implements Runnable {

  /** The name identifier for the account. */
  @Option(
      names = {"--name"},
      description = "Name identifier for the account",
      required = true)
  private String name;

  /** The password used to encrypt the private key. */
  @Option(
      names = {"--password"},
      description = "Password to encrypt the private key",
      required = true)
  private String password;

  /**
   * Executes the account creation command. Generates a new private key and saves it to an encrypted
   * keystore file.
   */
  @Override
  public void run() {
    // Generate a new private key
    String privateKey = KeyStoreUtils.generatePrivateKey();

    // Save the private key to a keystore file
    String keystoreFile = KeyStoreUtils.savePrivateKeyToFile(privateKey, password, name);

    System.out.println("Account created successfully.");
    System.out.println("Account name: " + name);
    System.out.println("Keystore file: " + keystoreFile);
  }
}
