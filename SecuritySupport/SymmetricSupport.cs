using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecuritySupport
{
    public class SymmetricSupport
    {
        private const string KeyBlobName = "SysInternal/AESKey";
        private const string IVBlobName = "SysInternal/AESIV";

        private AesManaged CurrProvider = new AesManaged() {Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7};
        private static RNGCryptoServiceProvider RndSupport = new RNGCryptoServiceProvider();

        public string EncryptStringToBase64(string plainText)
        {
            var encrypted = EncryptString(plainText);
            return Convert.ToBase64String(encrypted);
        }

        public byte[] EncryptString(string plainText)
        {
            var encryptor = CurrProvider.CreateEncryptor();

            // Create the streams used for encryption. 
            byte[] encrypted;
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt, Encoding.UTF8))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
            return encrypted;
        }

        public string DecryptString(byte[] cipherData)
        {
            var decryptor = CurrProvider.CreateDecryptor();
            string plainText;
            using (MemoryStream msDecrypt = new MemoryStream(cipherData))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8))
                    {

                        // Read the decrypted bytes from the decrypting stream 
                        // and place them in a string.
                        plainText = srDecrypt.ReadToEnd();
                    }
                }
            }
            return plainText;
        }


        public string DecryptStringFromBase64(string cipherText)
        {
            byte[] cipherData = Convert.FromBase64String(cipherText);
            return DecryptString(cipherData);
        }

        
        public byte[] EncryptData(byte[] plainText)
        {
            var encryptor = CurrProvider.CreateEncryptor();

            // Create the streams used for encryption. 
            byte[] encrypted;
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (BinaryWriter swEncrypt = new BinaryWriter(csEncrypt))
                    {

                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
            return encrypted;
        }

        public byte[] DecryptData(byte[] cipherText)
        {
            var decryptor = CurrProvider.CreateDecryptor();

            using (MemoryStream plainTextStream = new MemoryStream())
            {
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (BinaryReader srDecrypt = new BinaryReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            //plainText = srDecrypt.ReadBytes(int.MaxValue);
                            srDecrypt.BaseStream.CopyTo(plainTextStream);
                            //plainText = srDecrypt.ReadBytes(1024*1024);
                        }
                    }
                }
                return plainTextStream.ToArray();
            }
        }


        public void InitializeFromSharedSecret(string textvalue)
        {
            SHA256 sha256 = new SHA256Managed();
            byte[] dataToHash = Encoding.UTF8.GetBytes(textvalue);
            //byte[] key = dataToHash.Take(16).ToArray();
            //byte[] iv = dataToHash.Skip(16).ToArray();
            byte[] hash = sha256.ComputeHash(dataToHash);
            InitializeFromKeyAndIV(hash);
        }

        public void InitializeFromKeyAndIV(byte[] keyAndIV)
        {
            CurrProvider.KeySize = 128;
            byte[] key = keyAndIV.Take(16).ToArray();
            byte[] iv = keyAndIV.Skip(16).ToArray();
            CurrProvider.Key = key;
            CurrProvider.IV = iv;
        }

        public void InitializeNew()
        {
            CurrProvider.KeySize = 128;
            CurrProvider.GenerateKey();
            CurrProvider.GenerateIV();
        }

        public static byte[] GetRandomBytes(int byteAmount)
        {
            byte[] result = new byte[byteAmount];
            RndSupport.GetBytes(result);
            return result;
        }

        public byte[] GetKeyWithIV()
        {
            return CurrProvider.Key.Concat(CurrProvider.IV).ToArray();
        }
    }
}