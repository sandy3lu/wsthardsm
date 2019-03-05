package com.yunjingit.common.crypto;


import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

public class TokenEccPublicKey implements ECPublicKey {

    private ECPublicKey publicKey;
    static final int SMMA_ECC_FP_256_PUBLIC_KEY_LEN = 32 * 2;

    private static X9ECParameters ecparam = CustomNamedCurves.getByName("sm2p256v1");
    private static ECDomainParameters domain = new ECDomainParameters(ecparam.getCurve(), ecparam.getG(), ecparam.getN());
    private SM2P256V1Curve curve =new SM2P256V1Curve();
    private String orikey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public ECPoint getW() {
        return publicKey.getW();
    }

    @Override
    public String getAlgorithm() {
        return publicKey.getAlgorithm();
    }


    @Override
    public String getFormat() {
        return publicKey.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return publicKey.getEncoded();
    }

    @Override
    public ECParameterSpec getParams() {
        return publicKey.getParams();
    }

    public TokenEccPublicKey(String pubkey){

        orikey = pubkey;

        if(pubkey.length()!=SMMA_ECC_FP_256_PUBLIC_KEY_LEN*2){
            throw new RuntimeException("public key length not fit");
        }
        String stringx =pubkey.substring(0,SMMA_ECC_FP_256_PUBLIC_KEY_LEN);
        String stringy = pubkey.substring(SMMA_ECC_FP_256_PUBLIC_KEY_LEN);

        BigInteger x = new BigInteger(1, ByteUtils.fromHexString(stringx));
        BigInteger y = new BigInteger(1,ByteUtils.fromHexString(stringy));

        org.bouncycastle.math.ec.ECPoint q = curve.createPoint(x,y);
        AsymmetricKeyParameter publicKeyinfo = new ECPublicKeyParameters(q,domain);
        try {
            SubjectPublicKeyInfo spk = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyinfo);
            publicKey = (ECPublicKey) BouncyCastleProvider.getPublicKey(spk);
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    public String getOrikey(){
        return orikey;
    }

    public ECPublicKey getPublicKey(){
        return publicKey;
    }

    public static String transformToTokenKey(BCECPublicKey publicKey){

        BigInteger x = publicKey.getQ().getAffineXCoord().toBigInteger();
        BigInteger y =publicKey.getQ().getAffineYCoord().toBigInteger();
        String strx = x.toString(16);
        while (strx.length()<SMMA_ECC_FP_256_PUBLIC_KEY_LEN){
            strx = "0" + strx;
        }

        String stry = y.toString(16);
        while (stry.length()<SMMA_ECC_FP_256_PUBLIC_KEY_LEN){
            stry = "0" + stry;
        }

        String pubkey = strx + stry;
        return pubkey;
    }

}
