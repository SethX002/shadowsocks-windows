using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shadowsocks.Encryption.Stream;

namespace Shadowsocks.Test
{
    [TestClass]
    public class HttpMixEncryptorTest
    {
        [TestMethod]
        public void TestHttpMixEncryptor_EncryptDecrypt()
        {
            // Arrange
            string password = "testpassword";
            string method = "http_mix";
            string plainText = "Hello, World!";
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            var encryptor = new HttpMixEncryptor(method, password);
            var decryptor = new HttpMixEncryptor(method, password);

            // Act
            byte[] encrypted = new byte[plainBytes.Length + 512]; // header overhead
            encryptor.Encrypt(plainBytes, plainBytes.Length, encrypted, out int encLen);
            byte[] decrypted = new byte[encLen];
            decryptor.Decrypt(encrypted, encLen, decrypted, out int decLen);

            // Assert
            string decryptedText = Encoding.UTF8.GetString(decrypted, 0, decLen);
            Assert.AreEqual(plainText, decryptedText, "Decrypted text should match original");
        }

        [TestMethod]
        public void TestHttpMixEncryptor_LargeData()
        {
            // Arrange
            string password = "testpassword";
            string method = "http_mix";
            // 创建一个较大的测试数据
            byte[] plainBytes = new byte[4096];
            new Random().NextBytes(plainBytes); // 随机填充数据
            
            var encryptor = new HttpMixEncryptor(method, password);
            var decryptor = new HttpMixEncryptor(method, password);

            // Act
            byte[] encrypted = new byte[plainBytes.Length + 512]; // header overhead
            encryptor.Encrypt(plainBytes, plainBytes.Length, encrypted, out int encLen);
            byte[] decrypted = new byte[encLen];
            decryptor.Decrypt(encrypted, encLen, decrypted, out int decLen);

            // Assert
            Assert.AreEqual(plainBytes.Length, decLen, "Decrypted length should match original");
            for (int i = 0; i < plainBytes.Length; i++)
            {
                Assert.AreEqual(plainBytes[i], decrypted[i], $"Mismatch at position {i}");
            }
        }

        [TestMethod]
        public void TestHttpMixEncryptor_MultipleChunks()
        {
            // Arrange
            string password = "testpassword";
            string method = "http_mix";
            string plainText1 = "First chunk of data";
            string plainText2 = "Second chunk of data";
            byte[] plainBytes1 = Encoding.UTF8.GetBytes(plainText1);
            byte[] plainBytes2 = Encoding.UTF8.GetBytes(plainText2);
            
            var encryptor = new HttpMixEncryptor(method, password);
            var decryptor = new HttpMixEncryptor(method, password);

            // Act - First chunk
            byte[] encrypted1 = new byte[plainBytes1.Length + 512]; // header overhead
            encryptor.Encrypt(plainBytes1, plainBytes1.Length, encrypted1, out int encLen1);
            byte[] decrypted1 = new byte[encLen1];
            decryptor.Decrypt(encrypted1, encLen1, decrypted1, out int decLen1);

            // Act - Second chunk
            byte[] encrypted2 = new byte[plainBytes2.Length + 512]; // header overhead
            encryptor.Encrypt(plainBytes2, plainBytes2.Length, encrypted2, out int encLen2);
            byte[] decrypted2 = new byte[encLen2];
            decryptor.Decrypt(encrypted2, encLen2, decrypted2, out int decLen2);

            // Assert
            string decryptedText1 = Encoding.UTF8.GetString(decrypted1, 0, decLen1);
            string decryptedText2 = Encoding.UTF8.GetString(decrypted2, 0, decLen2);
            Assert.AreEqual(plainText1, decryptedText1, "First decrypted chunk should match original");
            Assert.AreEqual(plainText2, decryptedText2, "Second decrypted chunk should match original");
        }

        [TestMethod]
        public void TestHttpMixEncryptor_EmptyData()
        {
            // Arrange
            string password = "testpassword";
            string method = "http_mix";
            byte[] plainBytes = new byte[0]; // 空数据
            
            var encryptor = new HttpMixEncryptor(method, password);
            var decryptor = new HttpMixEncryptor(method, password);

            // Act
            byte[] encrypted = new byte[512]; // 只有头部开销
            encryptor.Encrypt(plainBytes, plainBytes.Length, encrypted, out int encLen);
            byte[] decrypted = new byte[encLen];
            decryptor.Decrypt(encrypted, encLen, decrypted, out int decLen);

            // Assert
            Assert.AreEqual(0, decLen, "Decrypted length should be 0 for empty input");
        }

        [TestMethod]
        public void TestHttpMixEncryptor_DifferentPasswords()
        {
            // Arrange
            string password1 = "password1";
            string password2 = "password2";
            string method = "http_mix";
            string plainText = "Secret message";
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            
            var encryptor = new HttpMixEncryptor(method, password1);
            var decryptor = new HttpMixEncryptor(method, password2); // 不同的密码

            // Act
            byte[] encrypted = new byte[plainBytes.Length + 512];
            encryptor.Encrypt(plainBytes, plainBytes.Length, encrypted, out int encLen);
            byte[] decrypted = new byte[encLen];
            decryptor.Decrypt(encrypted, encLen, decrypted, out int decLen);

            // Assert
            if (decLen > 0)
            {
                string decryptedText = Encoding.UTF8.GetString(decrypted, 0, decLen);
                Assert.AreNotEqual(plainText, decryptedText, "Different passwords should produce different results");
            }
            // Note: 在某些情况下，解密可能会失败，导致 decLen = 0，这也是预期行为
        }
    }
}
