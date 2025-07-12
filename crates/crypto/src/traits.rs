pub trait Kem {
    type PublicKey;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;

    /// Generate a new Kyber768 keypair
    fn generate_keypair() -> (Self::PublicKey, Self::SecretKey);

    /// Encapsulate a shared secret to a public key
    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret);

    /// Decapsulate a ciphertext using a secret key
    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Self::SharedSecret;
}
