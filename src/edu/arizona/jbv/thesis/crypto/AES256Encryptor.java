package edu.arizona.jbv.thesis.crypto;

import java.io.IOException;

import org.jorgecastle.crypto.BlockCipher;
import org.jorgecastle.crypto.DataLengthException;
import org.jorgecastle.crypto.InvalidCipherTextException;
import org.jorgecastle.crypto.engines.AESEngine;
import org.jorgecastle.crypto.paddings.PKCS7Padding;
import org.jorgecastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.jorgecastle.crypto.params.KeyParameter;

/**
 * This class uses the BouncyCastle AES classes to simplify AES encryption.
 * Currently, the key is hard-coded for use with this prototype, so this class
 * is not suitable for use in high security situations. The comments in the
 * constructor explain further.
 * 
 * Based on code found here:
 * http://technotes.tostaky.biz/2012/08/aes-256-symmetric-encryption-with.html
 * 
 * @author Jorge Vergara
 * 
 */
public class AES256Encryptor extends Encryptor {

	private BlockCipher AESCipher;
	private PaddedBufferedBlockCipher pbbc;
	private KeyParameter key;

	public AES256Encryptor() {
		AESCipher = new AESEngine();

		// the following three lines generate a random key, which is secure, but
		// is likely not desired for communication between two different parties
		//
		// KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		// keyGen.init(256);
		// SecretKey sk = keyGen.generateKey();
		//
		// instead, this constructor makes a simple key that is standard to all
		// communication in this prototype
		//
		// a better method would be to use a key exchange protocol like
		// Diffie-Hellman for communicating this key between the server and
		// client, although one still needs to be careful to avoid weaknesses
		// such as man in the middle attacks
		byte[] dummyKey = new byte[32];
		for (int i = 0; i < 32; i++) {
			dummyKey[i] = (byte) i;
		}

		this.pbbc = new PaddedBufferedBlockCipher(AESCipher, new PKCS7Padding());
		this.key = new KeyParameter(dummyKey);
	}

	public byte[] encrypt(Object o) {
		try {
			return processing(objectToByte(o), true);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	public byte[] decrypt(Object o) {
		return processing((byte[]) o, false);
	}

	private byte[] processing(byte[] input, boolean encrypt) {
		pbbc.init(encrypt, key);

		byte[] output = new byte[pbbc.getOutputSize(input.length)];
		// includes padding
		int bytesWrittenOut = pbbc.processBytes(input, 0, input.length, output,
				0);

		try {
			bytesWrittenOut += pbbc.doFinal(output, bytesWrittenOut);
		} catch (DataLengthException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
		}

		// removes the padding
		byte[] out = new byte[bytesWrittenOut];
		System.arraycopy(output, 0, out, 0, bytesWrittenOut);
		return output;
	}
}
