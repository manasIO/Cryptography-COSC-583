package crpyto.public_key_cryptography;

import java.math.BigInteger;
import java.util.Random;



public class RSA {

    
    public static void main(String args[]){
        BigInteger two = new BigInteger("2");
        Random rnd = new Random();
        BigInteger p = new BigInteger("0");
        BigInteger q = new BigInteger("0");
        BigInteger phi = new BigInteger("0");
        BigInteger n = new BigInteger("8843717107642638399335175568966837980155875365773249015251449315708041343367711725470384271725737590321890824143885251133898406427658296437114322172059359877911465858031490624852194779351234765457268911538565292954997995905126268116768594076057037948872239598828446935954369858414143871061876775789609343697303444586355328478413611969360502077680513221550905472517162511699680249613031971655340313361769061260628405600816010807096290638016609003800273833177441981772589749178028044345383567412397135597479326062903548551208731416000635109519019520533711976136804225636373241480532304631657157248030912997134412632471");
        BigInteger e = new BigInteger("65537");
        p = BigInteger.probablePrime(1024, rnd);
        q = BigInteger.probablePrime(1024, rnd);         

        phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        int count = 0;
        //System.out.println("Looking for GCD(phi,e)==1 ...");
    
        // while(!gcd(phi,e).equals(BigInteger.ONE)){
        //     p = BigInteger.probablePrime(1024, rnd);
        //     q = BigInteger.probablePrime(1024, rnd);       
        //     phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        //    // e = e.add(BigInteger.ONE);
        //     count++;
        //     System.out.println(count);
        // }       
        System.out.println("\ne value: "+e);
       // System.out.println("\nP value: "+p);
       // System.out.println("\nQ value: "+q);
       // System.out.println("\nPhi value: "+phi);
        System.out.println("\nN value:"+n);
        
      //  BigInteger x = new BigInteger("72");
        //BigInteger y = new BigInteger("5");
       // System.out.println("GCD : "+gcd(x,y));
        //BigInteger[] arr = gcd2(phi, e);
    
        // System.out.println("\nExtended Euclidean result : "+arr[0]);
        // System.out.println("\n"+arr[1]);
        // System.out.println("\n"+arr[2]);
        BigInteger d = new BigInteger("919632148077949565763907739178006329779548813918011078305974138067813628256571942705352225640644241848782916009896363679715544498596079927658179434557342227565598666745267690134850655679672016213608917590602598097079685400513229430944015878485873836482663424722154902856844692083744914800596460427028818488729131467305524902509357928705214314701843944468238229309293193742174165160074823670552012361253382225502522090147716991299712220340831374697141983334490411395972553636040724317554750330938760768422165018178926322060593028721613749407468366241647263091478192811859703074624110070503593240188385051615761382473");
        String mm = "";
        String msg = "sarcodictyum";
        for(int i=0;i<msg.length();i++){
            char ch = msg.charAt(i);
            mm += (ch-0);
        }
        
        BigInteger m = new BigInteger("35708582117990668681854154093");
       // BigInteger neww = new BigInteger(mm, 2);
    
        System.out.println("Message string: "+mm);

        // For encryption using   c = m^e(mod(n))
        BigInteger c = new BigInteger("0");
        c = m.modPow(e, n);
        System.out.println("Encryption: "+ c.toString());

        // For decryption using   d = c^d(mod(n))
        BigInteger dec = new BigInteger("0");
        BigInteger text = new BigInteger("5177192908229238182040028431892006990076529143454446751300107781226876968234845520931338633170531484543812660950886599501537457080233789985555187038475772222189494102260490410314282125286690121667698468005044692897186787793921130409378812664679845357677869247724626097813084809346775139980391779824644913657403344618222196912506283262424050067765511929839366614316774984059335190223988982137714955522535649325437227578441472751278626953107039338410436642669068306263735473859643065574874302264504118048876276316214908225906793163657554734422638810053767218428768878030028631482837129654798108155361568413690488519772");
        dec = text.modPow(d, n);
        System.out.println("Decryption: "+dec.toString());
        int val = dec.intValue();
        
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


    static BigInteger gcd(BigInteger a, BigInteger b){
        if(b==BigInteger.ZERO){
            return a;
        }
        return gcd(b, a.mod(b));
    }

    static BigInteger[] gcd2(BigInteger p, BigInteger q) {
        if (q == BigInteger.ZERO)
           return new BigInteger[] { p, BigInteger.ONE, BigInteger.ZERO };
  
        BigInteger[] vals = gcd2(q, p.mod(q));
        BigInteger d = vals[0];
        BigInteger s = vals[2];
        BigInteger t = vals[1].subtract((p.divide(q)).multiply(vals[2])) ;
        return new BigInteger[] { d, s, t };
     }

     
     
}


