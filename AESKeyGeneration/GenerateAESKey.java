package AESKeyGeneration;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class GenerateAESKey {
	public static void main(String args[]) throws FileNotFoundException {

		try {

			KeyGenerator key = KeyGenerator.getInstance("AES"); // AES Algorithm
			key.init(128); // Setting the length of AES Key
			SecretKey sk = key.generateKey();

			byte[] keyBytes = sk.getEncoded();
			System.out.println("Key -> " + keyBytes + ", Size -> " + keyBytes.length);

			DataOutputStream out = new DataOutputStream(new FileOutputStream(
					"AESKey"));

			out.write(keyBytes);
			out.flush();
			out.close();

		} catch (NoSuchAlgorithmException | IOException e) {

			System.out.println(e);
		}

	}
}
