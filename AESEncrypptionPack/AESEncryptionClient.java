package AESEncrypptionPack;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

public class AESEncryptionClient {

	/* Client Side */

	private static byte[] getKeyFromFile() throws IOException {

		/* Get the AES Key from local file */
		File f = new File("q3\\AESKey");
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

	private static byte[] encrypt(String value) throws IOException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {

		// Get the key from file AESKey
		byte[] keyBytes = getKeyFromFile();
		SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, spec);

		// Being encrypted the data
		byte[] encryptedData = cipher.doFinal(value.getBytes());
		System.out.println("After being encrypted -> " + encryptedData);

		return encryptedData;
	}

	private static byte[] decrypt(byte[] encryptedValue) throws IOException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		byte[] keyBytes = getKeyFromFile();

		/* Decrypted Value by Key */
		SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, spec);
		byte[] originalValue = cipher.doFinal(encryptedValue);
		System.out.println("After being encrypted value -> " + originalValue);

		return originalValue;
	}

	private static boolean checkFieldType(String value) {
		// Check the value is a integer value or not
		try {

			int valNum = Integer.parseInt(value);
			System.out.println("value -> " + valNum);

			return true;

		} catch (Exception e) {
			return false;
		}
	}

	public static void main(String[] argv) throws IOException {

		// Initialize the JPanel interface //
		JPanel panel = new JPanel();
		JLabel blank = new JLabel(" ");
		JLabel result = new JLabel("Get Result from Server : ");
		JLabel locationLabel1 = new JLabel("Location");
		JLabel value1Label1 = new JLabel("Value 1");
		JLabel value1Label2 = new JLabel("Value 2");
		JTextField locationField = new JTextField(20);
		JTextField value1Field = new JTextField(20);
		JTextField value2Field = new JTextField(20);
		JButton okButton = new JButton("Calculate");
		JButton cancelButton = new JButton("Cancel");
		JFrame frame = new JFrame("Socket Calculator");

		// Cancel button management //
		cancelButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				frame.dispose();
			}
		});

		// okButton event management //
		okButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {

				if (checkFieldType(value1Field.getText())
						&& checkFieldType(value2Field.getText())) {
					result.setText("Get Result from Server : "
							+ getEncrytedSum(locationField.getText(), 12345,
									value1Field.getText(),
									value2Field.getText()));
				} else {
					result.setText("Get Result from Server : MUST BE INTEGER");
				}
			}
		});

		// Add the components to JPanel //
		panel.add(locationLabel1);
		panel.add(locationField);
		panel.add(value1Label1);
		panel.add(value1Field);
		panel.add(value1Label2);
		panel.add(value2Field);
		panel.add(okButton);
		panel.add(cancelButton);
		panel.add(blank);
		panel.add(result);

		// Frame layout configuration //
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.add(panel);
		frame.setSize(300, 200);
		frame.setVisible(true);

	}

	public static String getEncrytedSum(String location, int port,
			String value1, String value2) {

		Socket sc = null;

		try {

			// Setting the host of server
			InetAddress add = InetAddress.getByName(location);
			SocketAddress sc_add = new InetSocketAddress(add, port);
			sc = new Socket();
			int timeout = 2000; // timeout 2s
			System.out.println("Connecting....");

			// Connect with server
			sc.connect(sc_add, timeout);
			System.out.println(sc.getLocalAddress() + " Connect to "
					+ sc.getInetAddress());

			// Transfer Data to Server
			DataOutputStream out = new DataOutputStream(sc.getOutputStream());
			byte[] encryptedDataFromClient = encrypt(value1 + "+" + value2);
			System.out.println("Encrypted Data -> " + encryptedDataFromClient);
			System.out.println("Decrypted Data -> "
					+ new String(decrypt(encryptedDataFromClient)));
			out.writeUTF(parseByte2HexStr(encryptedDataFromClient));
			out.flush();

			// Receive data from server
			DataInputStream in = new DataInputStream(sc.getInputStream());
			String sum = new String(decrypt(parseHexStr2Byte(in.readUTF())));
			System.out.println("sum ¡G" + sum);
			return sum;

		} catch (SocketTimeoutException e) {

			// Set connection time out
			System.out.println("Timeout");

		} catch (ConnectException ce) {

			System.out.println("Server is not available.");

		} catch (Exception e) {

			// General Exception Catch
			System.out.println(e);
			e.printStackTrace();

		}
		return "";
	}

	/*
	 * Because the encrypted byte array cannot be converted to String, so it
	 * needs to be change to HEX String, 2 bytes -> 16 bytes
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
}