package cz.peinlich;

import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;

import static cz.peinlich.BitcoinConstants.CURVE;

/**
 * @author Jiri
 */
public class BitcoinPublicKey implements PublicKey {
    protected LazyECPoint publicKey;

    public BitcoinPublicKey(LazyECPoint publicKey) {
        this.publicKey = publicKey;
    }

    public BitcoinPublicKey(ECPoint publicKey) {
        this(new LazyECPoint(publicKey));
    }

    public BitcoinPublicKey(ECPoint point, boolean compressed) {
        this(getPointWithCompression(point, compressed));

    }

    /**
     * Creates an ECKey that cannot be used for signing, only verifying signatures, from the given encoded point.
     * The compression state of pub will be preserved.
     */
    public static BitcoinPublicKey fromPublicOnly(byte[] pub) {
        return new BitcoinPublicKey(CURVE.getCurve().decodePoint(pub));
    }

    /**
     * Gets the raw public key value. This appears in transaction scriptSigs. Note that this is <b>not</b> the same
     * as the pubKeyHash/address.
     */
    public byte[] getPubKey() {
        return publicKey.getEncoded();
    }

    /**
     * Returns a copy of this key, but with the public point represented in uncompressed form. Normally you would
     * never need this: it's for specialised scenarios or when backwards compatibility in encoded form is necessary.
     */
    public BitcoinPublicKey decompress() {
        if (!publicKey.isCompressed())
            return this;
        else
            return new BitcoinPublicKey(decompressPoint(publicKey.get()));
    }


    /**
     * Utility for compressing an elliptic curve point. Returns the same point if it's already compressed.
     * See the ECKey class docs for a discussion of point compression.
     */
    public static ECPoint compressPoint(ECPoint point) {
        return getPointWithCompression(point, true);
    }

    public static LazyECPoint compressPoint(LazyECPoint point) {
        return point.isCompressed() ? point : new LazyECPoint(compressPoint(point.get()));
    }

    /**
     * Utility for decompressing an elliptic curve point. Returns the same point if it's already compressed.
     * See the ECKey class docs for a discussion of point compression.
     */
    public static ECPoint decompressPoint(ECPoint point) {
        return getPointWithCompression(point, false);
    }

    public static LazyECPoint decompressPoint(LazyECPoint point) {
        return !point.isCompressed() ? point : new LazyECPoint(decompressPoint(point.get()));
    }

    /** Gets the hash160 form of the public key (as seen in addresses). */
    public byte[] getPubKeyHash() {

        return Utils.sha256hash160(this.publicKey.getEncoded());
    }


    private static ECPoint getPointWithCompression(ECPoint point, boolean compressed) {
        if (point.isCompressed() == compressed)
            return point;
        point = point.normalize();
        BigInteger x = point.getAffineXCoord().toBigInteger();
        BigInteger y = point.getAffineYCoord().toBigInteger();
        return CURVE.getCurve().createPoint(x, y, compressed);
    }

}
