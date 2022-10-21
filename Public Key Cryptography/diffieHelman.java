package crpyto.public_key_cryptography;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;


public class diffieHelman {
    public static void main(String args []) throws NoSuchAlgorithmException{
        BigInteger two = new BigInteger("2");
        Random rnd = new Random();
        BigInteger prime = new BigInteger("92278822375486595023104238641647931475031984077679587165835083240483913221226669308547754406629188934670853427661354589117211612163134841813907747456233692580188404455903305934184920584031996773132439123323833587019138523418514119352648020524025538259804688953440833293231019228325890926230898747828608501939");
        //prime = BigInteger.probablePrime(1024, rnd);
        //System.out.println("Random prime: "+prime);
       //// BigInteger q = new BigInteger("0");
        //q = ((prime.subtract(BigInteger.ONE)).divide(two)); // (p-1)/2
        int count = 0,k=40;           
        // while(isProbablePrime(q,k)==false){
        //         System.out.println(count++);
        //         prime = BigInteger.probablePrime(1024, rnd);
        //         q = ((prime.subtract(BigInteger.ONE)).divide(two));
        //         continue;           
        // }      
        System.out.println("\nPrime value: "+prime);
        //System.out.println("Confirm: "+millerRabinTest(prime));
        //System.out.println("q value : "+q);
        //System.out.println("q: "+millerRabinTest(q));



        // Random 'PKa' private key
        BigInteger PKa = new BigInteger("74020918924906972730419622802372730743172699029172037508354170198447720013653");
        //PKa = BigInteger.probablePrime(256, rnd);
        System.out.println("Private Key: "+PKa);

        // Public key calculation
        BigInteger g = new BigInteger("5");
        BigInteger publicKeyA = new BigInteger("0");
        publicKeyA = modularExponentiation(g, PKa, prime);
        System.out.println("\nPublic keyA: "+publicKeyA);

        //Bob's public key
        BigInteger publicKeyB = new BigInteger("30075732033094743506185409044020004498058482457082730653786274547744695053447570246616947677674510359716626851651302954148498065214486494352883436469235683756313381443883182290266111205157487122084479235668909708856921481928167333464577931499839646453821089230491073945170339899375477318901705283581186025533");
        BigInteger sharedKey = new BigInteger("0");
        sharedKey = modularExponentiation(publicKeyB, PKa, prime);
        System.out.println("Shared Key: "+sharedKey);

        // generating SHA-256 hash
        String hash = toHexString(getSHA(sharedKey.toString()));
        System.out.println("Hash value: "+hash);

        String symmetricEncryptionKey = "";
        for(int i=0;i<32;i++){
            symmetricEncryptionKey += hash.charAt(i);
        }
        System.out.println("Symmetric Encrypting Key: "+symmetricEncryptionKey);

        // finally we can use the 'Symmetric Encryption key' and the provided IV in the python code
        // we will get the decrypted message


    }

    static boolean millerRabinTest(BigInteger p){
            BigInteger num = new BigInteger("0");
            num = p.subtract(BigInteger.ONE);
            int s = 0;
            BigInteger two = new BigInteger("2");
            if(p.mod(two)==BigInteger.ZERO) return false;
            BigInteger res = new BigInteger("0");
            while(true){
                if(num.mod(two.pow(s))==BigInteger.ZERO){
                    res = num.divide(two.pow(s));                    
                }else{
                    break;
                }
                s++;
            }
            s=s-1;
           // System.out.println("s: "+s);
           // System.out.println("res: "+res);
            BigInteger min = new BigInteger("2");
            int k = 40;
            BigInteger bigInteger = num.subtract(min);
            Random rnd = new Random();
            int len = num.bitLength();
            
            //System.out.println("random a : "+a);
            BigInteger b = new BigInteger("0");
            BigInteger minusOne = new BigInteger("0");
            minusOne = p.subtract(BigInteger.ONE);
            while(k!=0){
                BigInteger a = new BigInteger(len,rnd);
                if(a.compareTo(min)<0){
                    a = a.add(min);
                }
                if(a.compareTo(bigInteger)>=0){
                    a = a.mod(bigInteger).add(min);
                }   
                b = modularExponentiation(a, res, p);
                if(b.equals(BigInteger.ONE) || b.equals(minusOne)){
                    return true;       
                }
                while(s-1!=0){
                   // b = modularExponentiation(b, two, p);
                    b = (b.multiply(b)).mod(p);
                   // System.out.println(b);
                    if(b.equals(minusOne)){
                        return true;   
                    }          
                    s--;    
                }
                k--;
            }
            return false;
    }

    static BigInteger modularExponentiation(BigInteger a, BigInteger m, BigInteger n){
        BigInteger product;       
        product = new BigInteger("1");

        String eBits = m.toString(2);
        for(int i=eBits.length()-1;i>=0;i--){
            if(eBits.charAt(i)=='1'){
                product = (product.multiply(a)).mod(n);
            }
            a = a.multiply(a).mod(n);
        }
        return product;
    }

    public static byte[] getSHA(String input) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String toHexString(byte[] hash){
        BigInteger number = new BigInteger(1, hash);
        StringBuilder hexString = new StringBuilder(number.toString(16));
        while(hexString.length()<64){
            hexString.insert(0, '0');
        }
        return hexString.toString();
    }

    public static BigInteger generateRandom(BigInteger min, BigInteger max){
        Random rnd = new Random();
        BigInteger res;
        do {
            res = new BigInteger(max.bitLength(),rnd);
        }while(res.compareTo(min)<0 || res.compareTo(max)>0);
        return res;
    }

    public static boolean isProbablePrime(BigInteger n, int k){
        BigInteger two = new BigInteger("2");
        int s = 0;
        BigInteger d = n.subtract(BigInteger.ONE);
        while(d.mod(two).equals(BigInteger.ZERO)){
            s++;
            d = d.divide(two);
        }
        for(int i=0;i<k;i++){
            BigInteger a = generateRandom(two, n.subtract(BigInteger.ONE));
            BigInteger x = a.modPow(d, n);
            if(x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE)))
            continue;
            int r=0;
            for(;r<s;r++){
                x = x.modPow(two,n);
                if(x.equals(BigInteger.ONE)) return false;
                if(x.equals(n.subtract(BigInteger.ONE))) break;
            }
            if(r==s) return false;
        }
        return true;

    }
      

    
}
