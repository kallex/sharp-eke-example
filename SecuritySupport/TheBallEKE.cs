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
            EKEAlice alice = new EKEAlice(ekeContext: instance);
            EKEBob bob = new EKEBob(ekeContext: instance);
            // Hook message senders
            alice.SendMessageToBob = msg =>
            {
                bob.LatestMessageFromAlice = msg;
                bob.WaitForAlice = false;
            };
            bob.SendMessageToAlice = msg =>
            {
                alice.LatestMessageFromBob = msg;
                alice.WaitForBob = false;
            };
            bool ekeInProgress = true;
            int aliceActionIX = 0;
            int bobActionIX = 0;
            while (ekeInProgress)
            {
                bool alicesTurn = alice.IsDoneWithEKE == false && alice.WaitForBob == false;
                bool bobsTurn = !alicesTurn;
                if (alicesTurn)
                {
                    do
                    {
                        alice.AlicesActions[aliceActionIX++]();
                    } while (alice.IsDoneWithEKE == false && alice.WaitForBob == false);
                }
                else
                {
                    do
                    {
                        bob.BobsActions[bobActionIX++]();
                    } while (bob.IsDoneWithEKE == false && bob.WaitForAlice == false);
                }
                ekeInProgress = alice.IsDoneWithEKE == false || bob.IsDoneWithEKE == false;
            }
            bool ekeSuccess = true;
#if never
            instance.Alice1_1_GenerateKeyPair();
            instance.Alice1_2_EncryptPublicKeyWithS();
            instance.Alice1_3_SendEncryptedPublicKeyToBob(msgToBob =>
                {
                    instance.Bob.AlicesEncryptedPublicKey = msgToBob;
                });
            instance.Bob2_1_DecryptAlicesEncryptedPublicKey();
            instance.Bob2_2_GenerateRandomSessionKeyWithIV();
            instance.Bob2_3_EncryptSessionKey();
            instance.Bob2_4_SendEncryptedSessionKeyToAlice(msgToAlice =>
                {
                    instance.Alice.EncryptedSessionKey = msgToAlice;
                });
            instance.Alice3_1_DecryptSessionKey();
            instance.Alice3_2_GenerateAliceRandomValue();
            instance.Alice3_3_EncryptAliceRandomValueWithSessionKey();
            instance.Alice3_4_SendEncryptedAliceRandomToBob(msgToBob =>
                {
                    instance.Bob.AlicesEncryptedRandom = msgToBob;
                });
            instance.Bob4_1_DecryptAlicesEncryptedRandom();
            instance.Bob4_2_GenerateBobsRandomAndCombineWithAlicesRandom();
            instance.Bob4_3_SendBothRandomsEncryptedToAlice(msgToAlice =>
                {
                    instance.Alice.AlicesRandomWithBobsRandomEncrypted = msgToAlice;
                });
            instance.Alice5_1_DecryptBothRandoms();
            instance.Alice5_2_VerifyAliceRandomInCombinedRandom();
            instance.Alice5_3_ExtractBobsRandom();
            instance.Alice5_4_EncryptBobsRandom();
            instance.Alice5_5_SendEncryptedBobsRandomToBob(msgToBob =>
                {
                    instance.Bob.BobsRandomFromAliceEncrypted = msgToBob;
                });
            instance.Bob6_1_DecryptBobsRandomFromAlice();
            instance.Bob6_2_VerifyBobsRandom();
#endif
        }

        public delegate void NegotiationAction();


        private SymmetricSupport SharedSecretEnc;

        public class EKEAlice
        {
            public TheBallEKE EKEContext;

            public EKEAlice(TheBallEKE ekeContext)
            {
                EKEContext = ekeContext;
                AlicesActions = new NegotiationAction[]
                    {
                        Alice1_1_GenerateKeyPair, Alice1_2_EncryptPublicKeyWithS, Alice1_3_SendEncryptedPublicKeyToBob,

                        Alice3_0_GetEncryptedSessionKeyFromBob, Alice3_1_DecryptSessionKey,
                        Alice3_2_GenerateAliceRandomValue,
                        Alice3_3_EncryptAliceRandomValueWithSessionKey, Alice3_4_SendEncryptedAliceRandomToBob,

                        Alice5_0_GetAlicesRandomWithBobsRandomEncryptedFromBob, Alice5_1_DecryptBothRandoms,
                        Alice5_2_VerifyAliceRandomInCombinedRandom,
                        Alice5_3_ExtractBobsRandom, Alice5_4_EncryptBobsRandom, Alice5_5_SendEncryptedBobsRandomToBob,

                        AliceX_DoneWithEKE
                    };
            }

            private void AliceX_DoneWithEKE()
            {
                IsDoneWithEKE = true;
            }

            public NegotiationAction[] AlicesActions;

            public Action<byte[]> SendMessageToBob;
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
            public bool WaitForBob;
            public bool IsDoneWithEKE;
            public byte[] LatestMessageFromBob;

            private void Alice5_5_SendEncryptedBobsRandomToBob()
            {
                SendMessageToBob(BobsRandomEncrypted);
            }

            private void Alice5_4_EncryptBobsRandom()
            {
                BobsRandomEncrypted = SessionKeyEnc.EncryptData(BobsRandom);
            }

            private void Alice5_3_ExtractBobsRandom()
            {
                BobsRandom = AlicesRandomWithBobsRandom.Skip(16).ToArray();
            }

            private void Alice5_2_VerifyAliceRandomInCombinedRandom()
            {
                var alicesRandomExtracted = AlicesRandomWithBobsRandom.Take(16);
                if (AlicesRandom.SequenceEqual(alicesRandomExtracted) == false)
                    throw new SecurityException("EKE negotiation failed");
            }

            private void Alice5_0_GetAlicesRandomWithBobsRandomEncryptedFromBob()
            {
                AlicesRandomWithBobsRandomEncrypted = LatestMessageFromBob;
            }

            private void Alice5_1_DecryptBothRandoms()
            {
                AlicesRandomWithBobsRandom = SessionKeyEnc.DecryptData(AlicesRandomWithBobsRandomEncrypted);
            }

            private void Alice3_4_SendEncryptedAliceRandomToBob()
            {
                SendMessageToBob(AlicesRandomEncrypted);
                WaitForBob = true;
            }

            private void Alice3_3_EncryptAliceRandomValueWithSessionKey()
            {
                AlicesRandomEncrypted = SessionKeyEnc.EncryptData(AlicesRandom);
            }

            private void Alice3_2_GenerateAliceRandomValue()
            {
                AlicesRandom = SymmetricSupport.GetRandomBytes(16);
            }

            private void Alice3_0_GetEncryptedSessionKeyFromBob()
            {
                EncryptedSessionKey = LatestMessageFromBob;
            }

            private void Alice3_1_DecryptSessionKey()
            {
                var sessionKeyAndIV = PublicAndPrivateKeys.Decrypt(EncryptedSessionKey, false);
                SessionKeyEnc = new SymmetricSupport();
                SessionKeyEnc.InitializeFromKeyAndIV(sessionKeyAndIV);
            }

            private void Alice1_3_SendEncryptedPublicKeyToBob()
            {
                SendMessageToBob(EncryptedPublicKey);
                WaitForBob = true;
            }

            private void Alice1_2_EncryptPublicKeyWithS()
            {
                string rsaPublicKey = PublicAndPrivateKeys.ToXmlString(false);
                EncryptedPublicKey = EKEContext.SharedSecretEnc.EncryptString(rsaPublicKey);
            }

            private void Alice1_1_GenerateKeyPair()
            {
                using (var rsa = new RSACryptoServiceProvider(1024))
                {
                    try
                    {
                        PublicAndPrivateKeys = rsa;
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }
            }



        }

        public class EKEBob
        {
            public TheBallEKE EKEContext;
            public NegotiationAction[] BobsActions;

            public EKEBob(TheBallEKE ekeContext)
            {
                EKEContext = ekeContext;
                BobsActions = new NegotiationAction[]
                    {
                        Bob2_0_GetAlicesEncryptedPublicKeyFromAlice, Bob2_1_DecryptAlicesEncryptedPublicKey,
                        Bob2_2_GenerateRandomSessionKeyWithIV, Bob2_3_EncryptSessionKey,
                        Bob2_4_SendEncryptedSessionKeyToAlice,

                        Bob4_0_GetAlicesRandomEncryptedFromAlice, Bob4_1_DecryptAlicesEncryptedRandom,
                        Bob4_2_GenerateBobsRandomAndCombineWithAlicesRandom, Bob4_3_SendBothRandomsEncryptedToAlice,

                        Bob6_0_GetBobsRandomEncryptedFromAlice, Bob6_1_DecryptBobsRandomFromAlice,
                        Bob6_2_VerifyBobsRandom,

                        BobX_DoneWithEKE
                    };
            }

            private void BobX_DoneWithEKE()
            {
                IsDoneWithEKE = true;
            }

            public Action<byte[]> SendMessageToAlice;
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
            public byte[] LatestMessageFromAlice;
            public bool WaitForAlice;
            public bool IsDoneWithEKE;

            private void Bob6_2_VerifyBobsRandom()
            {
                if (BobsRandom.SequenceEqual(BobsRandomFromAlice) == false)
                    throw new SecurityException("EKE negotiation failed");
            }

            private void Bob6_1_DecryptBobsRandomFromAlice()
            {
                BobsRandomFromAlice = SessionKeyEnc.DecryptData(BobsRandomFromAliceEncrypted);
            }

            private void Bob6_0_GetBobsRandomEncryptedFromAlice()
            {
                BobsRandomFromAliceEncrypted = LatestMessageFromAlice;
            }

            private void Bob4_3_SendBothRandomsEncryptedToAlice()
            {
                SendMessageToAlice(AlicesRandomWithBobsRandomEncrypted);
                WaitForAlice = true;
            }

            private void Bob4_2_GenerateBobsRandomAndCombineWithAlicesRandom()
            {
                BobsRandom = SymmetricSupport.GetRandomBytes(16);
                AlicesRandomWithBobsRandom = AlicesRandom.Concat(BobsRandom).ToArray();
                AlicesRandomWithBobsRandomEncrypted = SessionKeyEnc.EncryptData(AlicesRandomWithBobsRandom);
            }

            private void Bob4_1_DecryptAlicesEncryptedRandom()
            {
                AlicesRandom = SessionKeyEnc.DecryptData(AlicesEncryptedRandom);
            }

            private void Bob4_0_GetAlicesRandomEncryptedFromAlice()
            {
                AlicesEncryptedRandom = LatestMessageFromAlice;
            }

            private void Bob2_4_SendEncryptedSessionKeyToAlice()
            {
                SendMessageToAlice(EncryptedSessionKey);
                WaitForAlice = true;
            }

            private void Bob2_3_EncryptSessionKey()
            {
                byte[] sessionKeyWithIV = SessionKeyEnc.GetKeyWithIV();
                var result = AlicesPublicKey.Encrypt(sessionKeyWithIV, false);
                EncryptedSessionKey = result;
            }

            private void Bob2_2_GenerateRandomSessionKeyWithIV()
            {
                SessionKeyEnc = new SymmetricSupport();
                SessionKeyEnc.InitializeNew();
            }

            private void Bob2_1_DecryptAlicesEncryptedPublicKey()
            {
                string alicesPublicKey = EKEContext.SharedSecretEnc.DecryptString(AlicesEncryptedPublicKey);
                AlicesPublicKey = new RSACryptoServiceProvider();
                AlicesPublicKey.FromXmlString(alicesPublicKey);
            }

            private void Bob2_0_GetAlicesEncryptedPublicKeyFromAlice()
            {
                AlicesEncryptedPublicKey = LatestMessageFromAlice;
            }


        }


        private void InitiateCurrentSymmetricFromSecret(string textvalue)
        {
            SharedSecretEnc = new SymmetricSupport();
            SharedSecretEnc.InitializeFromSharedSecret(textvalue);
        }


    }
}
