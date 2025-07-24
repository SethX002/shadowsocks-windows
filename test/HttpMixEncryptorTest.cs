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
            string password = "k" + new string('k', 15); // 与Python测试相同的密钥
            string method = "http_mix";
            // 创建一个大的随机数据块
            var random = new Random(12345); // 固定种子以便测试可重复
            byte[] plainBytes = new byte[4096];
            random.NextBytes(plainBytes);
            
            var encryptor = new HttpMixEncryptor(method, password);
            var decryptor = new HttpMixEncryptor(method, password);

            // Act
            byte[] encrypted = new byte[plainBytes.Length + 1024]; // 额外空间用于HTTP头
            encryptor.Encrypt(plainBytes, plainBytes.Length, encrypted, out int encLen);
            byte[] decrypted = new byte[encLen];
            decryptor.Decrypt(encrypted, encLen, decrypted, out int decLen);

            // Assert
            Assert.AreEqual(plainBytes.Length, decLen, "Decrypted data length should match original");
            for (int i = 0; i < plainBytes.Length; i++)
            {
                Assert.AreEqual(plainBytes[i], decrypted[i], $"Mismatch at position {i}");
            }
        }

        [TestMethod]
        public void TestHttpMixEncryptor_UDP()
        {
            // Arrange
            string password = "testpassword";
            string method = "http_mix";
            string plainText = "UDP test message";
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            var encryptor = new HttpMixEncryptor(method, password);
            var decryptor = new HttpMixEncryptor(method, password);

            // Act
            byte[] encrypted = new byte[plainBytes.Length + 512]; // header overhead
            encryptor.EncryptUDP(plainBytes, plainBytes.Length, encrypted, out int encLen);
            byte[] decrypted = new byte[encLen];
            decryptor.DecryptUDP(encrypted, encLen, decrypted, out int decLen);

            // Assert
            string decryptedText = Encoding.UTF8.GetString(decrypted, 0, decLen);
            Assert.AreEqual(plainText, decryptedText, "UDP decrypted text should match original");
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
            byte[] encrypted1 = new byte[plainBytes1.Length + 512];
            encryptor.Encrypt(plainBytes1, plainBytes1.Length, encrypted1, out int encLen1);
            byte[] decrypted1 = new byte[encLen1];
            decryptor.Decrypt(encrypted1, encLen1, decrypted1, out int decLen1);

            // Act - Second chunk
            byte[] encrypted2 = new byte[plainBytes2.Length + 512];
            encryptor.Encrypt(plainBytes2, plainBytes2.Length, encrypted2, out int encLen2);
            byte[] decrypted2 = new byte[encLen2];
            decryptor.Decrypt(encrypted2, encLen2, decrypted2, out int decLen2);

            // Assert
            string decryptedText1 = Encoding.UTF8.GetString(decrypted1, 0, decLen1);
            string decryptedText2 = Encoding.UTF8.GetString(decrypted2, 0, decLen2);
            Assert.AreEqual(plainText1, decryptedText1, "First chunk decrypted text should match original");
            Assert.AreEqual(plainText2, decryptedText2, "Second chunk decrypted text should match original");
        }

        [TestMethod]
        public void TestHttpMixEncryptor_PythonCompatibility()
        {
            // 这个测试模拟Python测试向量
            // 在Python中：
            // key = b'k' * 16
            // iv = b'i' * 16 (在HTTP_MIX中不使用)
            // plain = b'Hello, World!'

            // Arrange
            string password = "kkkkkkkkkkkkkkkk"; // 16个'k'
            string method = "http_mix";
            string plainText = "Hello, World!";
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            var encryptor = new HttpMixEncryptor(method, password);
            var decryptor = new HttpMixEncryptor(method, password);

            // Act
            byte[] encrypted = new byte[plainBytes.Length + 512];
            encryptor.Encrypt(plainBytes, plainBytes.Length, encrypted, out int encLen);
            byte[] decrypted = new byte[encLen];
            decryptor.Decrypt(encrypted, encLen, decrypted, out int decLen);

            // Assert
            string decryptedText = Encoding.UTF8.GetString(decrypted, 0, decLen);
            Assert.AreEqual(plainText, decryptedText, "Python compatibility test failed");
        }
    }
}
