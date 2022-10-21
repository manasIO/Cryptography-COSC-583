package crpyto.public_key_cryptography;

import java.math.BigInteger;
import java.util.Random;
 
public class primalityTesting {   // 100% working
    public static void main(String args []){
            BigInteger p = new BigInteger("9572189876543234567889"); // prime value
            BigInteger num = new BigInteger("0");
            num = p.subtract(BigInteger.ONE);
            int k = 0;
            BigInteger two = new BigInteger("2");
            BigInteger res = new BigInteger("0");
            while(true){
                if(num.mod(two.pow(k))==BigInteger.ZERO){
                    res = num.divide(two.pow(k));                    
                }else{
                    break;
                }
                k++;
            }
            k=k-1;
            //System.out.println("k: "+k);
            //System.out.println("res: "+res);
            BigInteger min = new BigInteger("2");
            
            BigInteger bigInteger = num.subtract(min);
            Random rnd = new Random();
            int len = num.bitLength();
            BigInteger a = new BigInteger(len,rnd);
            if(a.compareTo(min)<0){
                a = a.add(min);
            }
            if(a.compareTo(bigInteger)>=0){
                a = a.mod(bigInteger).add(min);
            }

            //BigInteger aa = new BigInteger("21906436");

            if(millerRabinTest(p)){
                System.out.println("Probable prime");
            }else{
                System.out.println("Composite");
            }  
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
                product = product.multiply(a).mod(n);
            }
            //System.out.println(a);
            //System.out.println(product+"\n");

            a = a.multiply(a).mod(n);
        }
        return product;
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
