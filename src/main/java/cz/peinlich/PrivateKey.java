package cz.peinlich;

/**
 * @author Jiri
 */
public interface PrivateKey {
    PublicKey getPublicKey();
    public byte[] getPrivKeyBytes();

}
