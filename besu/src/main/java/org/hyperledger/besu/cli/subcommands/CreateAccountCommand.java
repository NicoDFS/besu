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
 * Command line subcommand to create a new Ethereum account. This command generates a new private
 * key and stores it in an encrypted keystore file compatible with MetaMask and other Ethereum
 * wallets.
 *
 * <p>The command requires two parameters:
 *
 * <ul>
 *   <li>--name: A name identifier for the account
 *   <li>--password: A password to encrypt the private key
 * </ul>
 *
 * <p>The command will:
 *
 * <ul>
 *   <li>Generate a new private key
 *   <li>Create an encrypted keystore file in Web3 Secret Storage format
 *   <li>Output the Ethereum address and keystore file location
 * </ul>
 */
@Command(
    name = "create-account",
    description =
        "Creates a new account and stores the private key in a keystore file. "
            + "For passwords containing special characters, enclose the password in single quotes.",
    mixinStandardHelpOptions = true)
public class CreateAccountCommand implements Runnable {

  /**
   * Constructs a new CreateAccountCommand instance.
   *
   * <p>This command is used to generate new Ethereum accounts with encrypted keystore files.
   */
  public CreateAccountCommand() {
    // Default constructor
  }

  /**
   * The name identifier for the account.
   *
   * <p>This name is used as part of the keystore filename and can include spaces and special
   * characters.
   */
  @Option(
      names = {"--name"},
      description = "Name identifier for the account. Can include spaces and special characters.",
      required = true)
  private String name;

  /**
   * The password used to encrypt the private key in the keystore file.
   *
   * <p>For passwords containing special characters, they should be enclosed in single quotes.
   */
  @Option(
      names = {"--password"},
      description =
          "Password to encrypt the private key. For special characters, enclose in single quotes (e.g., 'my!pass@123').",
      required = true)
  private String password;

  /**
   * Executes the account creation command.
   *
   * <p>This method:
   *
   * <ul>
   *   <li>Generates a new private key
   *   <li>Saves it to an encrypted keystore file
   *   <li>Outputs the account address and keystore location
   * </ul>
   */
  @Override
  public void run() {
    // Generate a new private key
    String privateKey = KeyStoreUtils.generatePrivateKey();

    // Save the private key to a keystore file
    String keystoreFile = KeyStoreUtils.savePrivateKeyToFile(privateKey, password, name);

    // Get the address from KeyStoreUtils
    String address = KeyStoreUtils.getAddress(privateKey);

    System.out.println("Account created successfully.");
    System.out.println("Account name: " + name);
    System.out.println("Address: " + address);
    System.out.println("Keystore file: " + keystoreFile);
    System.out.println("\nIMPORTANT: Keep your keystore file and password safe!");
    System.out.println(
        "Your keystore file contains your private key encrypted with your password.");
    System.out.println("You can import this keystore file into most Ethereum wallets.");
  }
}
