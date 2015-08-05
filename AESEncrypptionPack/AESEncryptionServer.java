package AESEncrypptionPack;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryptionServer implements Runnable {

	private int port;
	private ServerSocket sc;

	public static void main(String[] args) throws IOException {

		// Create a new Thread for new client
		Thread socket_thread = new Thread(new AESEncryptionServer(12345));
		socket_thread.start();
	}

	public AESEncryptionServer(int p) throws IOException {

		// Set a port
		this.port = p;

		// Create Server Socket
		this.sc = new ServerSocket(port);
	}

	private int getSum(String i, String j) {
		int sum = Integer.parseInt(i) + Integer.parseInt(j);
		return sum;
	}

	private byte[] getKeyFromFile() throws IOException {

		/* Get the AES Key from local file */
		File f = new File("AESKey");
		FileInputStream fis = null;
		fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) f.length()];

		/* Read to be bytes */
		dis.readFully(keyBytes);
		dis.close();

		/* Display the key content */
		System.out.println("keyBytes -> " + keyBytes);
		return keyBytes;
	}

	private byte[] encrypt(String value) throws IOException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {

		byte[] keyBytes = this.getKeyFromFile();
		SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, spec);

		byte[] encryptedData = cipher.doFinal(value.getBytes());
		System.out.println("After being encrypted -> " + encryptedData);

		return encryptedData;
	}

	private byte[] decrypt(byte[] encryptedValue) throws IOException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		byte[] keyBytes = this.getKeyFromFile();

		/* Decrypted Value by Key */
		SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, spec);
		byte[] originalValue = cipher.doFinal(encryptedValue);
		System.out.println("After being encrypted value -> " + originalValue);

		return originalValue;
	}

	@Override
	public void run() {

		Socket con = null;

		while (true) {

			System.out.println("Waiting Connect .....");

			try {
				con = this.sc.accept();
				// Get IP of Client
				System.out.println(con.getInetAddress());

				// Get Data from Client
				System.out.println("Get Data from Client¡G");

				DataInputStream in = new DataInputStream(con.getInputStream());

				/*
				 * System.out.println(new String(decrypt(parseHexStr2Byte(in
				 * .readUTF()))));
				 */

				String[] parameters = new String(
						decrypt(parseHexStr2Byte(in.readUTF()))).split("\\+");

				System.out.println(parameters[0] + " + " + parameters[1]);
				System.out.println(getSum(parameters[0], parameters[1]));

				// Transfer data to client
				DataOutputStream out = new DataOutputStream(
						con.getOutputStream());

				// message which responses to client

				byte[] encryptedDataFromServer = encrypt(getSum(parameters[0],
						parameters[1]) + "");
				System.out.println("Encrypted Data -> "
						+ encryptedDataFromServer);
				System.out.println("Decrypted Data -> "
						+ new String(decrypt(encryptedDataFromServer)));
				out.writeUTF(parseByte2HexStr(encryptedDataFromServer));
				out.flush();
				
				// Close

				out.flush();
				con.close();

			} catch (Exception e) {
				System.out.println(e);
				e.printStackTrace();
			}
		}
	}

	/*
	 * When a Hex string comes from server, it needs to be changed to 2 bits
	 * data, 16 bytes -> 2 bytes
	 */
	public static byte[] parseHexStr2Byte(String hexStr) {
		if (hexStr.length() < 1)
			return null;
		byte[] result = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexStr.length() / 2; i++) {
			int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
			int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2),
					16);
			result[i] = (byte) (high * 16 + low);
		}
		return result;
	}

	/*
	 * Because the encrypted byte array cannot be converted to String, so it
	 * needs to be change to HEX String, 2 bits -> 16 bits
	 */
	public static String parseByte2HexStr(byte buf[]) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < buf.length; i++) {
			String hex = Integer.toHexString(buf[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}
}