package tr.edu.iyte.ceng.ceng471.crypto;

public interface SymmetricKey {
	public String getKey();
	public String encrypt(String plaintext);
	public String decrypt(String ciphertext);
}
