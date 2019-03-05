package com.yunjingit.common.crypto;


import com.yunjingit.common.Sm;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

public class TokenEccPrivateKey implements ECPrivateKey {

    static final int SMMA_ECC_FP_256_PRIVATE_KEY_LEN = 32;

    private ECPrivateKey key;
    private TokenEccPublicKey publicKey;

    private static X9ECParameters ecparam = CustomNamedCurves.getByName("sm2p256v1");
    private static ECDomainParameters domain = new ECDomainParameters(ecparam.getCurve(), ecparam.getG(), ecparam.getN());

    private String orikey;

    @Override
    public BigInteger getS() {
        return key.getS();
    }

    @Override
    public String getAlgorithm() {
        return key.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return key.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return key.getEncoded();
    }

    @Override
    public ECParameterSpec getParams() {
        return key.getParams();
    }

    TokenEccPrivateKey(Sm.KeyPair keyPair){

        orikey = keyPair.getPrivateKey();

        if(orikey.length()!=SMMA_ECC_FP_256_PRIVATE_KEY_LEN*2){
            throw new RuntimeException("private key length not fit");
        }
        // recover a private key from only D
        BigInteger d = new BigInteger(1,ByteUtils.fromHexString(orikey));
        ECPrivateKeyParameters param = new ECPrivateKeyParameters(d, domain);
        PrivateKeyInfo privateKeyInfo = null;
        try {
            privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(param);
            key = (ECPrivateKey) BouncyCastleProvider.getPrivateKey(privateKeyInfo);

        } catch (IOException e) {
            e.printStackTrace();
        }


        publicKey = new TokenEccPublicKey(keyPair.getPublicKey());
    }

    public String getOrikey(){
        return orikey;
    }

    public TokenEccPublicKey getPublicKey(){
        return publicKey;
    }

}
