package tr.edu.iyte.ceng.ceng471.crypto;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class DES implements SymmetricKey {
	private DESKeySpec desKeySpec;
	private IvParameterSpec ivSpec;
	private byte[] key;
	public DES(BigInteger key) {
		try {
			this.key = key.toByteArray();
			this.key = Arrays.copyOf(this.key, 8);
			this.desKeySpec = new DESKeySpec(this.key);
			this.ivSpec = new IvParameterSpec(this.key);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public String getKey() {
		return Base64.getEncoder().encodeToString(key);
	}
	
	@Override
	public String encrypt(String plaintext) {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
			SecretKey key = factory.generateSecret(this.desKeySpec);
			Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, this.ivSpec);
			return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes("UTF-8")));
		}  catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	@Override
	public String decrypt(String ciphertext) {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
			SecretKey key = factory.generateSecret(this.desKeySpec);
			Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, this.ivSpec);
			return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
		}  catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	public static void main(String[] args) throws Exception {
		DES des = new DES(BigInteger.valueOf(20));
		String data = "Hello, Alice!";
		String encrypted = des.encrypt(data);
		System.out.println("Message is " + data);
		System.out.println("Encrypted: " + encrypted);
		System.out.println("Alice decrypted as " + des.decrypt(encrypted));
	}
	

}
