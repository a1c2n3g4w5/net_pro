package rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;

public class RSA {
	private final static SecureRandom random = new SecureRandom();
    private BigInteger a;
    private BigInteger b;
    private BigInteger n;
    private BigInteger p;
    private BigInteger q;
    private Hashtable<String, BigInteger> publicKey;
    private Hashtable<String, BigInteger> privateKey;
    
    // ��ȡ˽Կ
    public Hashtable<String, BigInteger> getPrivateKey() {
        return privateKey;
    }

   //����˽Կ
    public void setPrivateKey(Hashtable<String, BigInteger> privateKey) {
        this.privateKey = privateKey;
        p = privateKey.get("p");
        q = privateKey.get("q");
        a = privateKey.get("a");
        n = p.multiply(q);
    }
    
    //��ȡ��Կ
    public Hashtable<String, BigInteger> getPublicKey() {
        return publicKey;
    }

    //���ù�Կ
    public void setPublicKey(Hashtable<String, BigInteger> publicKey) {
        this.publicKey = publicKey;
        n = publicKey.get("n");
        b = publicKey.get("b");
    }
    //��������ΪNλ�Ĺ�Կ��˽Կ

    public void genKey(int N)
    {
        // ��������N/2λ�Ĵ�����p��q
        p = BigInteger.probablePrime(N/2, random);
        q = BigInteger.probablePrime(N/2, random);
        // ���㣨p-1)*(q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        // ����ģ��p*q
        n = p.multiply(q);
        // �����һ��b��ʹ��gcd(b, phi) =1;
        // ͨ�õĹ�Կ��2^16 + 1=65537
        b = new BigInteger("65537");
        // �����a����b��ģn��
        a = b.modInverse(phi);
        publicKey = new Hashtable<String, BigInteger>();
        privateKey = new Hashtable<String, BigInteger>();
        publicKey.put("n", n);
        publicKey.put("b", b);
        privateKey.put("p", p);
        privateKey.put("q", q);
        privateKey.put("a", a);
    }
    //���ܺ���
    public byte[] pubEncrypt(byte[] plainText) {//��Կ����
        return new BigInteger(plainText).modPow(b, n).toByteArray();
    }
    public byte[] priEncrypt(byte[] plainText) {//˽Կ����
		return new BigInteger(plainText).modPow(a, n).toByteArray();
		
	}
    //���ܺ���
    public byte[] priDecrypt(byte[] cipherText) {//˽Կ����
        return new BigInteger(cipherText).modPow(a, n).toByteArray();
    }
    public byte[] pubDecrypt(byte[] cipherText) {//��Կ����
        return new BigInteger(cipherText).modPow(b, n).toByteArray();
    }
    
}
