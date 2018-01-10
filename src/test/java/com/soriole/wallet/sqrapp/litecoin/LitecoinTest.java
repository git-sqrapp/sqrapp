package com.soriole.wallet.sqrapp.litecoin;

import com.soriole.wallet.lib.KeyGenerator;
import com.soriole.wallet.lib.exceptions.ValidationException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.Security;

import static org.junit.Assert.assertEquals;

public class LitecoinTest {
    private Litecoin litecoin;
    KeyGenerator keyGenerator;

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public LitecoinTest() {
        litecoin = new Litecoin();
        X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
        String BITCOIN_SEED = "Litecoin seed";
        keyGenerator = new KeyGenerator(curve, BITCOIN_SEED);
    }

    @Test
    public void testWIF() throws ValidationException {
        String privateKeyHex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
        String privateKeyWif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

        BigInteger privateKey = new BigInteger(privateKeyHex, 16);
        String computedWif = litecoin.serializeWIF(keyGenerator.createECKeyPair(privateKey));
        System.out.println(computedWif);
        assertEquals(privateKeyWif, computedWif);

        KeyGenerator.ECKeyPair keyPair = litecoin.parseWIF(privateKeyWif);
        BigInteger privateKeyFromWif = keyPair.getPrivateKey();
        assertEquals(privateKey, privateKeyFromWif);
    }

    @Test
    public void testAddress() throws ValidationException {

        //String privateWif = "6vUDCKH8RHwwuopZsHzQoVrB6fvognoxvyJqMVRgRrKg1P7KLQL";
        String privateWif = "T916pwgBkDoXN5ex4yzQ4EL3a2pV4dCHsDXiRSTw2ghRAU1dcYXQ";

        String privateHex = "B18B7FBCB0E0CD61B86F4E93CB2A7F1721ABF32A84B7AE005ADC6BC0732014A5";
        String address1 = "LexZepkU7eTDDVoLyhwxSuxVEnqWoHmydS";
        String addressCompressed = "LVccEefoPy6jXvFRVkDR38EC4SZu79y82h";

        BigInteger privateKey = new BigInteger(privateHex, 16);
        System.out.println("length:"+privateKey.toByteArray().length);
        KeyGenerator.ECKeyPair keyPair = keyGenerator.createECKeyPair(privateKey, false);
        System.out.println("hex0:"+keyPair.getPrivateKey().toString(16));
        System.out.println("hex0:"+keyPair.getPublicKey().toString(16));

        KeyGenerator.ECKeyPair keyPair1 = litecoin.parseWIF(privateWif);

        String hex = keyPair1.getPrivateKey().toString(16);
        String hex2 = keyPair1.getPublicKey().toString(16);
        System.out.println("hex2:"+hex);
        System.out.println("hex2:"+hex2);

        byte[] pubBytes = keyPair.getPublic();
        String computedAddress = litecoin.address(pubBytes);
        String computedAddress2 = litecoin.address(keyPair.getPublicKey().toString(16));
        System.out.println(computedAddress);
        System.out.println(computedAddress2);
        assertEquals(address1, computedAddress);
    }

}
