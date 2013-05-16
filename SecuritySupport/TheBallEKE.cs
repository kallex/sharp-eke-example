using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecuritySupport
{
    /// <summary>
    /// Practical EKE (Encrypted Key Exchange), uses variation of DH-EKE (or this comment is outdated).
    /// 
    /// NOTE! Actually first implementation isn't DH-EKE, but just EKE with shared secret hashed to Key & IV for AES.
    /// 
    /// Anyway ground-up implemented EKE with following steps more or less:
    /// 1. Alice generates public/private key pair unique for the session Pa (private) and P'a (public) Alice encrypts public key using S and sends it to Bob.
    /// 2. Bob (knowing S) decrypts Alices message and recovers Alice's public key P'a. Bob generates random session key K. Bob encrypts K with Alice's public key P'a and sends it to Alice.
    /// 3. Alice decrypts the message and obtains K. Alice generates random string Ra, encrypts it with K and sends to bob
    /// 4. Bob decrypts the message to obtain Ra, generates another random Rb, encrypts both with K and sends the encrypted message to Alice.
    /// 5. Alice decrypts message, verifies her own Ra being valid in the message. She encrypts only Rb with K and sends to Bob.
    /// 6. Bob decrypts Rb and verifies his own Rb being valid.
    /// </summary>
    public class TheBallEKE
    {
        public static void TestExecution()
        {
            TheBallEKE instance = new TheBallEKE();
            instance.InitiateCurrentSymmetricFromSecret("testsecret");
            instance.Alice1_GenerateKeyPair();
            instance.Alice1_EncryptPublicKeyWithS();
            instance.Alice1_SendEncryptedPublicKeyToBob(msgToBob =>
                {
                    instance.Bob.AlicesEncryptedPublicKey = msgToBob;
                });
            instance.Bob2_DecryptAlicesEncryptedPublicKey();
            instance.Bob2_GenerateRandomSessionKeyWithIV();
            instance.Bob2_EncryptSessionKey();
            instance.Bob2_SendEncryptedSessionKeyToAlice(msgToAlice =>
                {
                    instance.Alice.EncryptedSessionKey = msgToAlice;
                });
            instance.Alice3_DecryptSessionKey();
            instance.Alice3_GenerateAliceRandomValue();
            instance.Alice3_EncryptAliceRandomValueWithSessionKey();
            instance.Alice3_SendEncryptedAliceRandomToBob(msgToBob =>
                {
                    instance.Bob.AlicesEncryptedRandom = msgToBob;
                });
            instance.Bob4_DecryptAlicesEncryptedRandom();
            instance.Bob4_GenerateBobsRandomAndCombineWithAlicesRandom();
            instance.Bob4_SendBothRandomsEncryptedToAlice(msgToAlice =>
                {
                    instance.Alice.AlicesRandomWithBobsRandomEncrypted = msgToAlice;
                });
            instance.Alice5_DecryptBothRandoms();
            instance.Alice5_VerifyAliceRandomInCombinedRandom();
            instance.Alice5_ExtractBobsRandom();
            instance.Alice5_EncryptBobsRandom();
            instance.Alice5_SendEncryptedBobsRandomToBob(msgToBob =>
                {
                    instance.Bob.BobsRandomFromAliceEncrypted = msgToBob;
                });
            instance.Bob6_DecryptBobsRandomFromAlice();
            instance.Bob6_VerifyBobsRandom();
        }


        AliceSupport Alice = new AliceSupport();
        BobSupport Bob = new BobSupport();
        private SymmetricSupport SharedSecretEnc;

        class AliceSupport
        {
            public SymmetricSupport SessionKeyEnc;

            //public byte[] SharedSecret;
            public RSACryptoServiceProvider PublicAndPrivateKeys;
            public byte[] EncryptedPublicKey;
            public byte[] EncryptedSessionKey;
            public byte[] AlicesRandom;
            public byte[] AlicesRandomEncrypted;
            public byte[] AlicesRandomWithBobsRandomEncrypted;
            public byte[] AlicesRandomWithBobsRandom;
            public byte[] BobsRandom;
            public byte[] BobsRandomEncrypted;
        }

        class BobSupport
        {
            public SymmetricSupport SessionKeyEnc;

            //public byte[] SharedSecret;
            public byte[] AlicesEncryptedPublicKey;
            public RSACryptoServiceProvider AlicesPublicKey;
            public byte[] EncryptedSessionKey;
            public byte[] AlicesEncryptedRandom;
            public byte[] AlicesRandom;
            public byte[] BobsRandom;
            public byte[] AlicesRandomWithBobsRandom;
            public byte[] AlicesRandomWithBobsRandomEncrypted;
            public byte[] BobsRandomFromAliceEncrypted;
            public byte[] BobsRandomFromAlice;
        }

        private void Bob6_VerifyBobsRandom()
        {
            if(Bob.BobsRandom.SequenceEqual(Bob.BobsRandomFromAlice) == false)
                throw new SecurityException("EKE negotiation failed");
        }

        private void Bob6_DecryptBobsRandomFromAlice()
        {
            Bob.BobsRandomFromAlice = Bob.SessionKeyEnc.DecryptData(Bob.BobsRandomFromAliceEncrypted);
        }

        private void Alice5_SendEncryptedBobsRandomToBob(Action<byte[]> sendMessageToBob)
        {
            sendMessageToBob(Alice.BobsRandomEncrypted);
        }
        
        private void Alice5_EncryptBobsRandom()
        {
            Alice.BobsRandomEncrypted = Alice.SessionKeyEnc.EncryptData(Alice.BobsRandom);
        }

        private void Alice5_ExtractBobsRandom()
        {
            Alice.BobsRandom = Alice.AlicesRandomWithBobsRandom.Skip(16).ToArray();
        }

        private void Alice5_VerifyAliceRandomInCombinedRandom()
        {
            var alicesRandomExtracted = Alice.AlicesRandomWithBobsRandom.Take(16);
            if(Alice.AlicesRandom.SequenceEqual(alicesRandomExtracted) == false)
                throw new SecurityException("EKE negotiation failed");
        }

        private void Alice5_DecryptBothRandoms()
        {
            Alice.AlicesRandomWithBobsRandom = Alice.SessionKeyEnc.DecryptData(Alice.AlicesRandomWithBobsRandomEncrypted);
        }

        private void Bob4_SendBothRandomsEncryptedToAlice(Action<byte[]> sendMessageToAlice)
        {
            sendMessageToAlice(Bob.AlicesRandomWithBobsRandomEncrypted);
        }

        private void Bob4_GenerateBobsRandomAndCombineWithAlicesRandom()
        {
            Bob.BobsRandom = SymmetricSupport.GetRandomBytes(16);
            Bob.AlicesRandomWithBobsRandom = Bob.AlicesRandom.Concat(Bob.BobsRandom).ToArray();
            Bob.AlicesRandomWithBobsRandomEncrypted = Bob.SessionKeyEnc.EncryptData(Bob.AlicesRandomWithBobsRandom);
        }

        private void Bob4_DecryptAlicesEncryptedRandom()
        {
            Bob.AlicesRandom = Bob.SessionKeyEnc.DecryptData(Bob.AlicesEncryptedRandom);
        }

        private void Alice3_SendEncryptedAliceRandomToBob(Action<byte[]> sendMessageToBob)
        {
            sendMessageToBob(Alice.AlicesRandomEncrypted);
        }

        private void Alice3_EncryptAliceRandomValueWithSessionKey()
        {
            Alice.AlicesRandomEncrypted = Alice.SessionKeyEnc.EncryptData(Alice.AlicesRandom);
        }

        private void Alice3_GenerateAliceRandomValue()
        {
            Alice.AlicesRandom = SymmetricSupport.GetRandomBytes(16);
        }

        private void Alice3_DecryptSessionKey()
        {
            var sessionKeyAndIV = Alice.PublicAndPrivateKeys.Decrypt(Alice.EncryptedSessionKey, false);
            Alice.SessionKeyEnc = new SymmetricSupport();
            Alice.SessionKeyEnc.InitializeFromKeyAndIV(sessionKeyAndIV);
        }

        private void Bob2_SendEncryptedSessionKeyToAlice(Action<byte[]> sendMessageToAlice)
        {
            sendMessageToAlice(Bob.EncryptedSessionKey);
        }

        private void Bob2_EncryptSessionKey()
        {
            byte[] sessionKeyWithIV = Bob.SessionKeyEnc.GetKeyWithIV();
            var result = Bob.AlicesPublicKey.Encrypt(sessionKeyWithIV, false);
            Bob.EncryptedSessionKey = result;
        }

        private void Bob2_GenerateRandomSessionKeyWithIV()
        {
            Bob.SessionKeyEnc = new SymmetricSupport();
            Bob.SessionKeyEnc.InitializeNew();
        }
        
        private void Bob2_DecryptAlicesEncryptedPublicKey()
        {
            string alicesPublicKey = SharedSecretEnc.DecryptString(Bob.AlicesEncryptedPublicKey);
            Bob.AlicesPublicKey = new RSACryptoServiceProvider();
            Bob.AlicesPublicKey.FromXmlString(alicesPublicKey);
        }

        private void Alice1_SendEncryptedPublicKeyToBob(Action<byte[]> sendMessageToBob)
        {
            sendMessageToBob(Alice.EncryptedPublicKey);
        }

        private void Alice1_EncryptPublicKeyWithS()
        {
            string rsaPublicKey = Alice.PublicAndPrivateKeys.ToXmlString(false);
            Alice.EncryptedPublicKey = SharedSecretEnc.EncryptString(rsaPublicKey);
        }

        private void Alice1_GenerateKeyPair()
        {
            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                try
                {
                    Alice.PublicAndPrivateKeys = rsa;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        private void InitiateCurrentSymmetricFromSecret(string textvalue)
        {
            SharedSecretEnc = new SymmetricSupport();
            SharedSecretEnc.InitializeFromSharedSecret(textvalue);
        }


    }
}
