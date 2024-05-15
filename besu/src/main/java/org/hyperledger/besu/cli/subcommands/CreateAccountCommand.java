package org.hyperledger.besu.cli.subcommands;

import org.hyperledger.besu.ethereum.api.util.KeyStoreUtils;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
    name = "create-account",
    description = "Creates a new account and stores the private key in a keystore file",
    mixinStandardHelpOptions = true)
public class CreateAccountCommand implements Runnable {

  @Option(
      names = {"--name"},
      description = "The name of the account",
      required = true)
  private String name;

  @Option(
      names = {"--password"},
      description = "The password to encrypt the private key",
      required = true)
  private String password;

  @Override
  public void run() {
    // Generate a new private key
    String privateKey = KeyStoreUtils.generatePrivateKey();

    // Save the private key to a keystore file
    String keystoreFile = KeyStoreUtils.savePrivateKeyToFile(privateKey, password);

    System.out.println("Account created successfully.");
    System.out.println("Keystore file: " + keystoreFile);
  }
}