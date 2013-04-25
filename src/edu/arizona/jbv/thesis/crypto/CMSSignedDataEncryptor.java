package edu.arizona.jbv.thesis.crypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.jorgecastle.cert.jcajce.JcaCertStore;
import org.jorgecastle.cert.jcajce.JcaCertStoreBuilder;
import org.jorgecastle.cms.CMSException;
import org.jorgecastle.cms.CMSProcessable;
import org.jorgecastle.cms.CMSProcessableByteArray;
import org.jorgecastle.cms.CMSSignedData;
import org.jorgecastle.cms.CMSSignedDataGenerator;
import org.jorgecastle.cms.CMSTypedData;
import org.jorgecastle.cms.SignerInformation;
import org.jorgecastle.cms.SignerInformationStore;
import org.jorgecastle.cms.SignerInformationVerifier;
import org.jorgecastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.jorgecastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.jorgecastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.jorgecastle.openssl.PEMDecryptorProvider;
import org.jorgecastle.openssl.PEMEncryptedKeyPair;
import org.jorgecastle.openssl.PEMKeyPair;
import org.jorgecastle.openssl.PEMParser;
import org.jorgecastle.openssl.jcajce.JcaPEMKeyConverter;
import org.jorgecastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.jorgecastle.operator.ContentSigner;
import org.jorgecastle.operator.OperatorCreationException;
import org.jorgecastle.operator.jcajce.JcaContentSignerBuilder;
import org.jorgecastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.jorgecastle.util.Store;
// this import appear unused but is necessary to register the provider
// import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This class does not truly encrypt data as such probably does not deserve to
 * extend the Encryptor class. However, to simplify the programming of the
 * prototype, the misnamed class seemed acceptable. This class takes objects and
 * signs them. The decrypt method returns the orginal data, after validating the
 * signature.
 * 
 * @author Jorge Vergara
 * 
 */
public class CMSSignedDataEncryptor extends Encryptor {

	private InputStream keyStoreStream;
	private InputStream keyFileStream;

	static {
		Security.insertProviderAt(
				new org.jorgecastle.jce.provider.BouncyCastleProvider(), 1);
	}

	public CMSSignedDataEncryptor(String keyStorePath, String keyFilePath) {
		try {
			keyStoreStream = new FileInputStream(keyStorePath);
			keyFileStream = new FileInputStream(keyFilePath);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public CMSSignedDataEncryptor(InputStream keyStoreStream,
			InputStream keyFileStream) {
		this.keyStoreStream = keyStoreStream;
		this.keyFileStream = keyFileStream;
	}

	@Override
	public Object encrypt(Object o) {
		try {
			byte[] objectToEncrypt = objectToByte(o);

			List<X509Certificate> certList = new ArrayList<X509Certificate>();
			CMSTypedData msg = new CMSProcessableByteArray(objectToEncrypt);

			KeyStore keystore = KeyStore.getInstance("jks");
			InputStream input = keyStoreStream;
			try {
				// password in all my generated keystores is 111111
				keystore.load(input, "111111".toCharArray());
			} catch (IOException e) {
				e.printStackTrace();
			}

			// this is the alias name I chose when creating the certificate
			X509Certificate signingCertificate = (X509Certificate) keystore
					.getCertificate("keystore.jks");

			certList.add(signingCertificate);

			Store certs = new JcaCertStore(certList);

			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			// get the private key
			Reader reader = new InputStreamReader(keyFileStream);
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
			PrivateKey pk = kp.getPrivate();
			ContentSigner sha1Signer = new JcaContentSignerBuilder(
					"SHA1withRSA").setProvider("JC").build(pk);

			gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider("JC")
							.build()).build(sha1Signer, signingCertificate));

			gen.addCertificates(certs);

			CMSSignedData sigData = gen.generate(msg, false);

			List<byte[]> list = new ArrayList<byte[]>();
			list.add(0, sigData.getEncoded());
			list.add(0, objectToEncrypt);

			return list;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * The object that should be passed in is an arraylist of byte arrays. The
	 * first element should have the CMSProcessable byte array (to be turned
	 * into a CMSProcessable), and the second element should have the getEncoded
	 * of the CMSSignedData
	 */
	@Override
	public byte[] decrypt(Object o) {

		@SuppressWarnings("unchecked")
		List<byte[]> list = (List<byte[]>) o;
		CMSSignedData s = null;
		try {

			s = new CMSSignedData(new CMSProcessableByteArray(list.get(0)),
					list.get(1));
		} catch (CMSException e) {
			e.printStackTrace();
		}

		Store certs = s.getCertificates();
		JcaCertStoreBuilder builder = new JcaCertStoreBuilder();

		CertStore certStoreCerts = null;
		try {
			certStoreCerts = builder.addCertificates(certs).build();
		} catch (GeneralSecurityException e2) {
			e2.printStackTrace();
		}

		SignerInformationStore signers = s.getSignerInfos();
		boolean verified = false;

		for (Iterator<?> i = signers.getSigners().iterator(); i.hasNext();) {
			SignerInformation signer = (SignerInformation) i.next();
			JcaX509CertSelectorConverter selector = new JcaX509CertSelectorConverter();
			X509CertSelector matcher = selector
					.getCertSelector(signer.getSID());

			Collection<? extends Certificate> certCollection = null;
			try {

				certCollection = certStoreCerts.getCertificates(matcher);
			} catch (CertStoreException e1) {
				e1.printStackTrace();
			}
			if (!certCollection.isEmpty()) {
				X509Certificate cert = (X509Certificate) certCollection
						.iterator().next();
				try {
					JcaSimpleSignerInfoVerifierBuilder verifier = new JcaSimpleSignerInfoVerifierBuilder();
					verifier.setProvider("JC");

					SignerInformationVerifier v = verifier.build(cert
							.getPublicKey());

					if (signer.verify(v)) {
						verified = true;
					}
				} catch (CMSException e) {
					e.printStackTrace();
				} catch (OperatorCreationException e) {
					e.printStackTrace();
				}
			}
		}

		if (!verified) {
			Exception e = new Exception("CMSSignedData not verified!");
			e.printStackTrace();
			return null;
		}
		CMSProcessable signedContent = s.getSignedContent();
		byte[] originalContent = (byte[]) signedContent.getContent();

		return originalContent;
	}
}
