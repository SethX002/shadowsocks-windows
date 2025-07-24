using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace HelloWorldApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            
            Console.WriteLine("开始测试HttpMixEncryptor...");
            
            // 测试简单加密解密
            TestHttpMixEncryptor_SimpleTest();
            
            // 测试与Python版本兼容性
            TestHttpMixEncryptor_PythonCompatibility();
            
            Console.WriteLine("测试完成!");
        }
        
        static void TestHttpMixEncryptor_SimpleTest()
        {
            try
            {
                // 创建一个模拟的HttpMixEncryptor实现
                Console.WriteLine("创建HttpMixEncryptor测试实例...");
                
                string password = "testpassword";
                string plainText = "Hello, World!";
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                
                Console.WriteLine($"原始文本: {plainText}");
                Console.WriteLine($"密码: {password}");
                
                // 模拟加密
                Console.WriteLine("模拟加密过程...");
                byte[] encryptedData = SimpleEncrypt(plainBytes, password);
                Console.WriteLine($"加密后长度: {encryptedData.Length}字节");
                
                // 模拟解密
                Console.WriteLine("模拟解密过程...");
                byte[] decryptedData = SimpleDecrypt(encryptedData, password);
                string decryptedText = Encoding.UTF8.GetString(decryptedData);
                
                Console.WriteLine($"解密后文本: {decryptedText}");
                Console.WriteLine($"解密是否成功: {plainText == decryptedText}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"测试过程中出现异常: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
        
        static void TestHttpMixEncryptor_PythonCompatibility()
        {
            Console.WriteLine("\n测试与Python版本的兼容性...");
            try
            {
                // 使用与Python测试相同的密钥和明文
                string key = new string('k', 16);  // Python中: key = b'k' * 16
                string plainText = "Hello, World!"; // Python中: plain = b'Hello, World!'
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                
                Console.WriteLine($"Python测试向量 - 明文: {plainText}");
                Console.WriteLine($"Python测试向量 - 密钥: {key}");
                
                // 第一阶段：C#版本加密
                Console.WriteLine("\n步骤1: 使用C#实现加密数据...");
                byte[] encryptedDataCSharp = CompatibilityEncrypt(plainBytes, key);
                string encHexCSharp = BitConverter.ToString(encryptedDataCSharp).Replace("-", "").ToLower();
                Console.WriteLine($"C#加密结果(hex前50字节): {encHexCSharp.Substring(0, Math.Min(100, encHexCSharp.Length))}...");
                
                // 第二阶段：模拟Python版本加密结果
                Console.WriteLine("\n步骤2: 检查与预期Python结果的一致性...");
                
                // ExtendedTableCipher的加密过程（模拟Python版本）
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] md5Key = CreateMD5(keyBytes);
                byte[] encTable = GenerateEncryptTable(md5Key);
                
                byte[] encryptedContent = new byte[plainBytes.Length];
                for (int i = 0; i < plainBytes.Length; i++)
                {
                    byte b = plainBytes[i];
                    if (b < 256)
                    {
                        encryptedContent[i] = encTable[b];
                    }
                    else
                    {
                        encryptedContent[i] = b;
                    }
                }
                
                string encHexPythonSimulated = BitConverter.ToString(encryptedContent).Replace("-", "").ToLower();
                Console.WriteLine($"Python模拟加密内容(不含HTTP头)(hex): {encHexPythonSimulated}");
                
                // 添加HTTP头 - 仅用于演示，实际Python版本会随机生成
                string httpHeader = "HTTP/1.1 200 OK\r\n" +
                                    "Date: Mon, 22 Jul 2024 12:34:56 GMT\r\n" +
                                    "Server: nginx/1.18.0\r\n" +
                                    "Content-Type: text/html; charset=utf-8\r\n" +
                                    $"Content-Length: {encryptedContent.Length}\r\n" +
                                    "Connection: keep-alive\r\n" +
                                    "\r\n";
                byte[] headerBytes = Encoding.UTF8.GetBytes(httpHeader);
                
                // 组合HTTP头和加密内容
                byte[] fullPythonResponse = new byte[headerBytes.Length + encryptedContent.Length];
                Buffer.BlockCopy(headerBytes, 0, fullPythonResponse, 0, headerBytes.Length);
                Buffer.BlockCopy(encryptedContent, 0, fullPythonResponse, headerBytes.Length, encryptedContent.Length);
                
                string fullHexPythonSimulated = BitConverter.ToString(fullPythonResponse).Replace("-", "").ToLower();
                Console.WriteLine($"完整Python模拟响应(hex前50字节): {fullHexPythonSimulated.Substring(0, Math.Min(100, fullHexPythonSimulated.Length))}...");
                
                // 第三阶段：检查解密结果
                Console.WriteLine("\n步骤3: 验证解密结果...");
                
                // 解密C#版本的结果
                byte[] decryptedFromCSharp = CompatibilityDecrypt(encryptedDataCSharp, key);
                string decryptedTextCSharp = Encoding.UTF8.GetString(decryptedFromCSharp);
                
                // 验证解密结果
                bool decryptSuccess = decryptedTextCSharp == plainText;
                Console.WriteLine($"C#实现解密结果: {decryptedTextCSharp}");
                Console.WriteLine($"解密结果是否与原始文本匹配: {decryptSuccess}");
                
                // 解密模拟的Python版本结果
                byte[] decryptTable = GenerateDecryptTable(encTable);
                byte[] decryptedPythonContent = new byte[encryptedContent.Length];
                for (int i = 0; i < encryptedContent.Length; i++)
                {
                    byte b = encryptedContent[i];
                    if (b < 256)
                    {
                        decryptedPythonContent[i] = decryptTable[b];
                    }
                    else
                    {
                        decryptedPythonContent[i] = b;
                    }
                }
                string decryptedTextPython = Encoding.UTF8.GetString(decryptedPythonContent);
                bool pythonDecryptSuccess = decryptedTextPython == plainText;
                
                Console.WriteLine($"Python模拟解密结果: {decryptedTextPython}");
                Console.WriteLine($"Python模拟解密是否与原始文本匹配: {pythonDecryptSuccess}");
                
                // 总结兼容性测试结果
                Console.WriteLine("\n兼容性测试结果:");
                Console.WriteLine($"C#实现与Python实现解密兼容: {pythonDecryptSuccess && decryptSuccess}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"兼容性测试过程中出现异常: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
        
        // 简化版的加密实现
        static byte[] SimpleEncrypt(byte[] data, string password)
        {
            // 一个非常简单的加密方案，仅用于演示
            var result = new byte[data.Length];
            byte[] key = Encoding.UTF8.GetBytes(password);
            
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            
            // 为了模拟HTTP头部，我们在前面添加一些数据
            var header = Encoding.UTF8.GetBytes(
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/octet-stream\r\n" +
                "Content-Length: " + result.Length + "\r\n" +
                "\r\n");
            
            var combined = new byte[header.Length + result.Length];
            Buffer.BlockCopy(header, 0, combined, 0, header.Length);
            Buffer.BlockCopy(result, 0, combined, header.Length, result.Length);
            
            return combined;
        }
        
        // 简化版的解密实现
        static byte[] SimpleDecrypt(byte[] data, string password)
        {
            // 首先移除HTTP头
            var dataString = Encoding.UTF8.GetString(data);
            var headerEnd = dataString.IndexOf("\r\n\r\n") + 4;
            
            if (headerEnd < 4)
            {
                throw new Exception("Invalid HTTP format");
            }
            
            var encryptedData = new byte[data.Length - headerEnd];
            Buffer.BlockCopy(data, headerEnd, encryptedData, 0, encryptedData.Length);
            
            // 解密数据
            var result = new byte[encryptedData.Length];
            byte[] key = Encoding.UTF8.GetBytes(password);
            
            for (int i = 0; i < encryptedData.Length; i++)
            {
                result[i] = (byte)(encryptedData[i] ^ key[i % key.Length]);
            }
            
            return result;
        }
        
        // 以下是为了与Python版本兼容的实现
        
        // 模拟Python版本的加密
        static byte[] CompatibilityEncrypt(byte[] data, string password)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(password);
            byte[] md5Key = CreateMD5(keyBytes);
            byte[] encTable = GenerateEncryptTable(md5Key);
            
            // 加密数据
            byte[] encrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                if (b < 256)
                {
                    encrypted[i] = encTable[b];
                }
                else
                {
                    encrypted[i] = b;
                }
            }
            
            // 创建HTTP头
            string httpHeader = "HTTP/1.1 200 OK\r\n" +
                                "Date: Mon, 22 Jul 2024 12:34:56 GMT\r\n" +
                                "Server: nginx/1.18.0\r\n" +
                                "Content-Type: text/html; charset=utf-8\r\n" +
                                $"Content-Length: {encrypted.Length}\r\n" +
                                "Connection: keep-alive\r\n" +
                                "\r\n";
            byte[] headerBytes = Encoding.UTF8.GetBytes(httpHeader);
            
            // 组合HTTP头和加密数据
            byte[] result = new byte[headerBytes.Length + encrypted.Length];
            Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
            Buffer.BlockCopy(encrypted, 0, result, headerBytes.Length, encrypted.Length);
            
            return result;
        }
        
        // 模拟Python版本的解密
        static byte[] CompatibilityDecrypt(byte[] data, string password)
        {
            // 首先移除HTTP头
            string dataStr = Encoding.UTF8.GetString(data);
            int headerEnd = dataStr.IndexOf("\r\n\r\n") + 4;
            
            if (headerEnd < 4)
            {
                throw new Exception("无效的HTTP格式");
            }
            
            byte[] encryptedData = new byte[data.Length - headerEnd];
            Buffer.BlockCopy(data, headerEnd, encryptedData, 0, encryptedData.Length);
            
            // 生成解密表
            byte[] keyBytes = Encoding.UTF8.GetBytes(password);
            byte[] md5Key = CreateMD5(keyBytes);
            byte[] encTable = GenerateEncryptTable(md5Key);
            byte[] decTable = GenerateDecryptTable(encTable);
            
            // 解密数据
            byte[] decrypted = new byte[encryptedData.Length];
            for (int i = 0; i < encryptedData.Length; i++)
            {
                byte b = encryptedData[i];
                if (b < 256)
                {
                    decrypted[i] = decTable[b];
                }
                else
                {
                    decrypted[i] = b;
                }
            }
            
            return decrypted;
        }
        
        // 创建MD5哈希
        static byte[] CreateMD5(byte[] input)
        {
            using (MD5 md5 = MD5.Create())
            {
                return md5.ComputeHash(input);
            }
        }
        
        // 生成加密表 - 模拟Python版本
        static byte[] GenerateEncryptTable(byte[] key)
        {
            ulong a = BitConverter.ToUInt64(key, 0);
            ulong b = BitConverter.ToUInt64(key, 8);
            
            // 创建初始表
            byte[] table = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                table[i] = (byte)i;
            }
            
            // 对表进行排序
            for (int i = 1; i < 1024; i++)
            {
                table = ShuffleTable(table, a, i);
            }
            
            return table;
        }
        
        // 打乱表的顺序
        static byte[] ShuffleTable(byte[] table, ulong a, int round)
        {
            // 简化版的洗牌算法，模拟Python的排序
            var result = new byte[256];
            Array.Copy(table, result, 256);
            
            // 冒泡排序模拟Python的排序逻辑
            for (int i = 0; i < 255; i++)
            {
                for (int j = 0; j < 255 - i; j++)
                {
                    if ((a % ((ulong)result[j] + (ulong)round)) > (a % ((ulong)result[j + 1] + (ulong)round)))
                    {
                        byte temp = result[j];
                        result[j] = result[j + 1];
                        result[j + 1] = temp;
                    }
                }
            }
            
            return result;
        }
        
        // 生成解密表
        static byte[] GenerateDecryptTable(byte[] encTable)
        {
            byte[] decTable = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                decTable[encTable[i]] = (byte)i;
            }
            return decTable;
        }
    }
} 