package tr.edu.iyte.ceng.ceng471.crypto;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class AES implements SymmetricKey {
    private SecretKeySpec secret;
    private byte[] key;
    private MessageDigest sha;
    
    public AES(BigInteger s) {
    	try {
    		key = s.toByteArray();
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			secret = new SecretKeySpec(key, "AES");
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
    }
    
    @Override
    public String getKey() {
    	return Base64.getEncoder().encodeToString(this.key);
    }
    
    @Override
    public String encrypt(String plainttext) {
        Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			return Base64.getEncoder().encodeToString(cipher.doFinal(plainttext.getBytes("UTF-8")));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
    }
    
    @Override
    public String decrypt(String ciphertext) {
        Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			 cipher.init(Cipher.DECRYPT_MODE, secret);
		     return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
    }

	public static void main(String[] args) {
		AES aes = new AES(BigInteger.valueOf(5));
		String data = "Hello, Alice!";
		String encrypted = aes.encrypt(data);
		System.out.println("Message is " + data);
		System.out.println("Encrypted: " + encrypted);
		System.out.println("Alice decrypted as " + aes.decrypt(encrypted));
		

	}

}
