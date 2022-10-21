package crpyto.public_key_cryptography;

import java.math.BigInteger;

public class modularExponentiation {
    public static void main(String args[]){
        BigInteger b, e, n, product;  // int the format: b^e (mod(n))
        b = new BigInteger("5");
        e = new BigInteger("145");
        n = new BigInteger("257");
        product = new BigInteger("1");

        String eBits = e.toString(2);
        //System.out.println(eBits);
        for(int i=eBits.length()-1;i>=0;i--){
            if(eBits.charAt(i)=='1'){
                product = product.multiply(b).mod(n);
            }
            System.out.println(b);
            System.out.println(product+"\n");

            b = b.multiply(b).mod(n);
        }
        System.out.println(product);
    }

}
