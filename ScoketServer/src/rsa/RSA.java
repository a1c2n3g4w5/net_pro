package rsa;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
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
    
    // 获取私钥
    public Hashtable<String, BigInteger> getPrivateKey() {
        return privateKey;
    }

   //设置私钥
    public void setPrivateKey(Hashtable<String, BigInteger> privateKey) {
        this.privateKey = privateKey;
        p = privateKey.get("p");
        q = privateKey.get("q");
        a = privateKey.get("a");
        n = p.multiply(q);
    }
    
    //获取公钥
    public Hashtable<String, BigInteger> getPublicKey() {
        return publicKey;
    }

    //设置公钥
    public void setPublicKey(Hashtable<String, BigInteger> publicKey) {
        this.publicKey = publicKey;
        n = publicKey.get("n");
        b = publicKey.get("b");
    }
    
    //产生长度为N位的公钥和私钥
    public void genKey(int N)
    {
        // 产生两个N/2位的大素数p和q
        p = BigInteger.probablePrime(N/2, random);
        q = BigInteger.probablePrime(N/2, random);
        // 计算（p-1)*(q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        // 计算模数p*q
        n = p.multiply(q);
        // 随便找一个b，使得gcd(b, phi) =1; 通用的公钥是2^16 + 1=65537
        b = new BigInteger("65537");
        // 计算出a，即b的模n逆
        a = b.modInverse(phi);
        publicKey = new Hashtable<String, BigInteger>();
        privateKey = new Hashtable<String, BigInteger>();
        publicKey.put("n", n);
        publicKey.put("b", b);
        privateKey.put("p", p);
        privateKey.put("q", q);
        privateKey.put("a", a);
    }
    //加密函数
    public byte[] pubEncrypt(byte[] plainText) {//公钥加密***
        return new BigInteger(plainText).modPow(b, n).toByteArray();
    }
    public byte[] priEncrypt(byte[] plainText) {//私钥加密
		return new BigInteger(plainText).modPow(a, n).toByteArray();
	}
    //解密函数
    public byte[] priDecrypt(byte[] cipherText) {//私钥解密***
        return new BigInteger(cipherText).modPow(a, n).toByteArray();
    }
    public byte[] pubDecrypt(byte[] cipherText) {//公钥解密
        return new BigInteger(cipherText).modPow(b, n).toByteArray();
    }
    @SuppressWarnings("deprecation")
	public static void main(String[] args){
    	RSA rsa=new RSA();
    	RSA rsa2=new RSA();
    	rsa.genKey(1024);
    	try {
//			byte[] buf=rsa.pubEncrypt(URLEncoder.encode("草泥马","gbk").getBytes("gbk"));
//			byte[] endb=rsa.priDecrypt(buf);
//			System.out.println(URLEncoder.encode("草泥马","gbk"));
//			System.out.println(buf);
//			System.out.println(endb);
//			System.out.println(new String(endb));
//			System.out.println(URLDecoder.decode(new String(endb), "gbk"));
			
			rsa2.setPublicKey(rsa.getPublicKey());
			byte[] buf2=rsa2.pubEncrypt(URLEncoder.encode("我酝酿d","gbk").getBytes("gbk"));
			byte[] endb2=rsa2.priDecrypt(buf2);
			System.out.println(URLEncoder.encode("无无无d","gbk"));
			System.out.println(buf2);
			System.out.println(endb2);
			System.out.println(new String(endb2));
			System.out.println(URLDecoder.decode(new String(endb2), "gbk"));
			
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
}
