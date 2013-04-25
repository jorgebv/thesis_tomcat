package edu.arizona.jbv.thesis.crypto;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.Reader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.jorgecastle.openssl.PEMDecryptorProvider;
import org.jorgecastle.openssl.PEMEncryptedKeyPair;
import org.jorgecastle.openssl.PEMKeyPair;
import org.jorgecastle.openssl.PEMParser;
import org.jorgecastle.openssl.jcajce.JcaPEMKeyConverter;
import org.jorgecastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

/**
 * This class is not used by the prototype, but remains in case it proves useful
 * to future versions or other developers. After further reading into RSA, it
 * does not seem useful to encrypt entire messages, but rather smaller things
 * such as keys. RSA is slower than symmetric cryptography methods. There is
 * also a length limit in that the size of the message to be encoded cannot be
 * larger than the key that is used. As such, this class as it is fails on
 * larger data, although this could easily be solved.
 * 
 * @author Jorge Vergara
 * 
 */
public class RSAEncryptor extends Encryptor {

	private PublicKey publicKey;
	private PrivateKey privateKey;

	public RSAEncryptor(String certFilePath, String privateKeyFilePath) {
		if (privateKeyFilePath != null) {
			try {
				Reader reader = new FileReader(privateKeyFilePath);
				PEMParser pemParser = new PEMParser(reader);
				Object object = pemParser.readObject();

				PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder()
						.build("1234".toCharArray());
				JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
						.setProvider("JC");
				KeyPair kp;
				if (object instanceof PEMEncryptedKeyPair) {
					kp = converter.getKeyPair(((PEMEncryptedKeyPair) object)
							.decryptKeyPair(decProv));
				} else {
					kp = converter.getKeyPair((PEMKeyPair) object);
				}

				pemParser.close();
				privateKey = kp.getPrivate();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		if (certFilePath != null) {
			InputStream inStream = null;
			try {
				inStream = new FileInputStream(certFilePath);
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				X509Certificate hrsA = (X509Certificate) cf
						.generateCertificate(inStream);
				publicKey = KeyFactory.getInstance("RSA").generatePublic(
						new X509EncodedKeySpec(hrsA.getEncoded()));
				inStream.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}

	public RSAEncryptor(byte[] encryptionKey, byte[] decryptionKey) {
		try {
			if (encryptionKey != null) {
				publicKey = KeyFactory.getInstance("RSA").generatePublic(
						new X509EncodedKeySpec(encryptionKey));
			}
			if (decryptionKey != null) {
				privateKey = KeyFactory.getInstance("RSA").generatePrivate(
						(new X509EncodedKeySpec(decryptionKey)));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public Object encrypt(Object o) {
		try {
			Cipher rsa;
			rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] returnVal = rsa.doFinal(objectToByte(o));

			return returnVal;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public byte[] decrypt(Object o) {
		try {
			Cipher rsa;
			rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] unencryted = rsa.doFinal((byte[]) o);

			return unencryted;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
