package com.example.crypto;


import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Arrays;

public class CliTool {
public static void main(String[] args) throws Exception {
if (args.length < 1) {
printUsageAndExit();
}


String cmd = args[0];
switch (cmd) {
case "gen-key":
// args: gen-key <bits> <keyfile>
if (args.length != 3) printUsageAndExit();
int bits = Integer.parseInt(args[1]);
Path keyOut = Path.of(args[2]);
byte[] key = KeyGen.generateRandomKey(bits);
Files.writeString(keyOut, Base64.getEncoder().encodeToString(key));
System.out.println("Wrote key to: " + keyOut.toAbsolutePath());
break;


case "encrypt":
// support both --keyfile and --passphrase
handleEncrypt(Arrays.copyOfRange(args, 1, args.length));
break;


case "decrypt":
handleDecrypt(Arrays.copyOfRange(args, 1, args.length));
break;


default:
System.err.println("Unknown command: " + cmd);
p
