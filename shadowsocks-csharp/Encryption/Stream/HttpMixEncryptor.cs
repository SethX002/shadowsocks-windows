using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Shadowsocks.Encryption.Stream
{
    public class HttpMixEncryptor : EncryptorBase, IDisposable
    {
        private const int CIPHER_HTTP_MIX = 1001;
        private static readonly Dictionary<string, EncryptorInfo> _ciphers = new Dictionary<string, EncryptorInfo>
        {
            { "http_mix", new EncryptorInfo("HTTP_MIX", 16, 16, CIPHER_HTTP_MIX) }
        };

        private ExtendedTableCipher _cipher;
        private bool _opEncrypt;
        private bool _haveHeader;
        private List<byte> _buffer = new List<byte>();
        
        // HTTP头列表，用于随机选择
        private static readonly string[] HTTP_HEADERS = new string[]
        {
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Charset: UTF-8,*;q=0.5",
            "Accept-Encoding: gzip,deflate,sdch",
            "Accept-Language: en-US,en;q=0.8,zh;q=0.6",
            "Connection: keep-alive",
            "Cookie: _ga=GA1.2.123456789.1234567890; _gid=GA1.2.123456789.1234567890",
            "Referer: https://www.bing.com/",
            "Cache-Control: max-age=0",
        };

        // 常见User-Agent列表，随机使用
        private static readonly string[] USER_AGENTS = new string[]
        {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        };

        // 常见的网站域名，用于伪装请求
        private static readonly string[] COMMON_DOMAINS = new string[]
        {
            "apps.microsoft.com",
            "www.bing.com",
            "www.freesound.org",
            "www.amazon.com",
            "www.anthropic.com",
            "www.kenney.nl",
            "brackeysgames.itch.io",
            "www.linkedin.com",
            "www.reddit.com",
            "www.upf.edu",
        };

        // 常见的HTTP路径，用于伪装请求
        private static readonly string[] COMMON_PATHS = new string[]
        {
            "/",
            "/index.html",
            "/news",
            "/article/latest",
            "/search?q=technology",
            "/login",
            "/about",
            "/contact",
            "/images/banner.jpg",
            "/css/style.css",
            "/js/main.js",
        };

        // 常见HTTP状态码和对应文本
        private static readonly Dictionary<int, string> STATUS_TEXTS = new Dictionary<int, string>
        {
            { 200, "OK" },
            { 301, "Moved Permanently" },
            { 302, "Found" },
            { 304, "Not Modified" },
            { 307, "Temporary Redirect" },
            { 404, "Not Found" }
        };

        // 常见HTTP状态码，大多数是200
        private static readonly int[] STATUS_CODES = new int[]
        {
            200, 200, 200, 200, 200, 301, 302, 304, 307, 404
        };

        // 扩展的table加密表缓存
        private static readonly Dictionary<string, Tuple<byte[], byte[]>> _cachedTables = new Dictionary<string, Tuple<byte[], byte[]>>();

        public HttpMixEncryptor(string method, string password) : base(method, password)
        {
            _opEncrypt = true; // 默认为加密模式
            _cipher = new ExtendedTableCipher(GetKey(password), _opEncrypt);
        }

        public static List<string> SupportedCiphers()
        {
            return new List<string>(_ciphers.Keys);
        }

        protected Dictionary<string, EncryptorInfo> getCiphers()
        {
            return _ciphers;
        }

        private static byte[] GetKey(string password)
        {
            // 使用MD5与Python代码一致
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        #region TCP
        public override void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // 加密并在需要时添加HTTP头
            var data = new byte[length];
            Buffer.BlockCopy(buf, 0, data, 0, length);
            var encrypted = _cipher.Encrypt(data);
            
            if (!_haveHeader)
            {
                // 随机决定是生成HTTP请求还是HTTP响应头
                byte[] header;
                var rand = new Random();
                if (rand.Next(2) == 0)
                {
                    header = GenerateHttpRequestHeader(encrypted.Length);
                }
                else
                {
                    header = GenerateHttpResponseHeader(encrypted.Length);
                }
                
                Buffer.BlockCopy(header, 0, outbuf, 0, header.Length);
                Buffer.BlockCopy(encrypted, 0, outbuf, header.Length, encrypted.Length);
                outlength = header.Length + encrypted.Length;
                _haveHeader = true;
            }
            else
            {
                Buffer.BlockCopy(encrypted, 0, outbuf, 0, encrypted.Length);
                outlength = encrypted.Length;
            }
        }

        public override void Decrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // 缓冲直到移除头部
            _buffer.AddRange(buf.Take(length));
            if (!_haveHeader)
            {
                var idx = IndexOf(_buffer, new byte[] { 13, 10, 13, 10 }); // \r\n\r\n
                if (idx >= 0)
                {
                    _buffer = _buffer.Skip(idx + 4).ToList();
                    _haveHeader = true;
                }
                else
                {
                    outlength = 0;
                    return;
                }
            }
            
            var decrypted = _cipher.Decrypt(_buffer.ToArray());
            Buffer.BlockCopy(decrypted, 0, outbuf, 0, decrypted.Length);
            outlength = decrypted.Length;
            _buffer.Clear();
        }
        #endregion

        #region UDP
        public override void EncryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // 对于UDP，我们使用一次性加密方法
            var data = new byte[length];
            Buffer.BlockCopy(buf, 0, data, 0, length);
            var encrypted = _cipher.Encrypt(data);
            
            // 随机决定是HTTP请求还是响应
            byte[] header;
            var rand = new Random();
            if (rand.Next(2) == 0)
            {
                header = GenerateHttpRequestHeader(encrypted.Length);
            }
            else
            {
                header = GenerateHttpResponseHeader(encrypted.Length);
            }
            
            Buffer.BlockCopy(header, 0, outbuf, 0, header.Length);
            Buffer.BlockCopy(encrypted, 0, outbuf, header.Length, encrypted.Length);
            outlength = header.Length + encrypted.Length;
        }

        public override void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // 对于UDP，我们需要一次性移除HTTP头并解密
            var data = new List<byte>(buf.Take(length));
            var idx = IndexOf(data, new byte[] { 13, 10, 13, 10 }); // \r\n\r\n
            if (idx >= 0)
            {
                data = data.Skip(idx + 4).ToList();
            }
            
            var decrypted = _cipher.Decrypt(data.ToArray());
            Buffer.BlockCopy(decrypted, 0, outbuf, 0, decrypted.Length);
            outlength = decrypted.Length;
        }
        #endregion

        #region IDisposable
        private bool _disposed;
        private readonly object _lock = new object();
        public override void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        ~HttpMixEncryptor()
        {
            Dispose(false);
        }
        protected virtual void Dispose(bool disposing)
        {
            lock (_lock)
            {
                if (_disposed) return;
                _disposed = true;
            }
        }
        #endregion

        // 辅助方法：查找字节模式的索引
        private static int IndexOf(List<byte> buffer, byte[] pattern)
        {
            for (int i = 0; i <= buffer.Count - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        // 生成HTTP请求头
        private static byte[] GenerateHttpRequestHeader(int dataLen)
        {
            var rand = new Random();
            string domain = COMMON_DOMAINS[rand.Next(COMMON_DOMAINS.Length)];
            string path = COMMON_PATHS[rand.Next(COMMON_PATHS.Length)];
            string userAgent = USER_AGENTS[rand.Next(USER_AGENTS.Length)];
            
            // 生成随机的X-Request-ID
            string requestId = string.Concat(Enumerable.Range(0, 32).Select(_ => rand.Next(16).ToString("x")));
            
            // 构建HTTP头
            var headers = new List<string>
            {
                $"GET {path} HTTP/1.1",
                $"Host: {domain}",
                $"User-Agent: {userAgent}",
                $"X-Request-ID: {requestId}"
            };
            
            // 随机添加2-5个额外的HTTP头
            int extraHeadersCount = rand.Next(2, 6);
            var shuffledHeaders = HTTP_HEADERS.OrderBy(_ => rand.Next()).ToArray();
            for (int i = 0; i < Math.Min(extraHeadersCount, shuffledHeaders.Length); i++)
            {
                headers.Add(shuffledHeaders[i]);
            }
            
            headers.Add($"Content-Length: {dataLen}");
            headers.Add("");
            headers.Add("");
            
            return Encoding.UTF8.GetBytes(string.Join("\r\n", headers));
        }

        // 生成HTTP响应头
        private static byte[] GenerateHttpResponseHeader(int dataLen)
        {
            var rand = new Random();
            
            // 随机选择HTTP状态码，大多数是200
            int status = STATUS_CODES[rand.Next(STATUS_CODES.Length)];
            string statusText = STATUS_TEXTS[status];
            
            // 构建HTTP响应头
            var headers = new List<string>
            {
                $"HTTP/1.1 {status} {statusText}",
                $"Date: {DateTime.UtcNow.ToString("r")}",
                "Server: nginx/1.18.0",
                "Content-Type: text/html; charset=utf-8",
                $"Content-Length: {dataLen}",
                "Connection: keep-alive",
            };
            
            // 随机添加缓存控制头
            if (rand.Next(2) == 0)
            {
                headers.Add("Cache-Control: no-store, no-cache, must-revalidate");
            }
            
            // 随机添加其他头
            if (rand.Next(2) == 0)
            {
                headers.Add("X-Frame-Options: SAMEORIGIN");
            }
            if (rand.Next(2) == 0)
            {
                headers.Add("X-Content-Type-Options: nosniff");
            }
            if (rand.Next(2) == 0)
            {
                headers.Add("X-XSS-Protection: 1; mode=block");
            }
            
            headers.Add("");  // 空行，表示头部结束
            headers.Add("");  // 为了生成双回车换行
            
            return Encoding.UTF8.GetBytes(string.Join("\r\n", headers));
        }

        // --- ExtendedTableCipher内部类 ---
        private class ExtendedTableCipher
        {
            private byte[] _encryptTable;
            private byte[] _decryptTable;
            private bool _opEncrypt;
            private byte[] _indexBuffer; // 用于跟踪使用了哪些索引
            
            public ExtendedTableCipher(byte[] key, bool opEncrypt)
            {
                _opEncrypt = opEncrypt;
                var tables = InitExtendedTable(key);
                _encryptTable = tables.Item1;
                _decryptTable = tables.Item2;
            }
            
            public byte[] Encrypt(byte[] data)
            {
                return Update(data);
            }
            
            public byte[] Decrypt(byte[] data)
            {
                return Update(data);
            }
            
            private byte[] Update(byte[] data)
            {
                if (data == null || data.Length == 0) return new byte[0];
                
                var result = new byte[data.Length];
                
                if (_opEncrypt)
                {
                    _indexBuffer = new byte[data.Length];
                    
                    for (int i = 0; i < data.Length; i++)
                    {
                        byte b = data[i];
                        if (b < 256)
                        {
                            result[i] = _encryptTable[b];
                            _indexBuffer[i] = 0; // 0表示使用基础表
                        }
                        else
                        {
                            result[i] = b;
                            _indexBuffer[i] = 255; // 255表示未加密
                        }
                    }
                }
                else
                {
                    for (int i = 0; i < data.Length; i++)
                    {
                        byte b = data[i];
                        if (b < 256)
                        {
                            result[i] = _decryptTable[b];
                        }
                        else
                        {
                            result[i] = b;
                        }
                    }
                }
                
                return result;
            }
            
            // 表生成逻辑
            private static Tuple<byte[], byte[]> InitExtendedTable(byte[] key)
            {
                string keyStr = Convert.ToBase64String(key);
                if (_cachedTables.ContainsKey(keyStr))
                {
                    return _cachedTables[keyStr];
                }
                
                // MD5哈希
                using (var md5 = MD5.Create())
                {
                    var s = md5.ComputeHash(key);
                    ulong a = BitConverter.ToUInt64(s, 0);
                    ulong b = BitConverter.ToUInt64(s, 8);
                    
                    // 基础table大小为256
                    int baseSize = 256;
                    // 扩展0.5倍，总大小为384
                    int extendedSize = baseSize + baseSize / 2;
                    
                    // 创建基础table
                    var table = Enumerable.Range(0, baseSize).Select(i => (byte)i).ToArray();
                    
                    // 对基础table排序
                    for (int i = 1; i < 1024; i++)
                    {
                        table = table.OrderBy(x => (int)(a % ((ulong)x + (ulong)i))).ToArray();
                    }
                    
                    // 扩展table：基于基础table生成额外的128个元素
                    // 使用不同的哈希算法来增加随机性
                    var extraTable = new List<byte>();
                    using (var sha256 = SHA256.Create())
                    {
                        sha256.TransformBlock(key, 0, key.Length, null, 0);
                        sha256.TransformFinalBlock(s, 0, s.Length);
                        var extraSeed = sha256.Hash;
                        
                        ulong c = BitConverter.ToUInt64(extraSeed, 0);
                        ulong d = BitConverter.ToUInt64(extraSeed, 8);
                        
                        // 生成额外的128个元素
                        for (int i = 0; i < baseSize / 2; i++)
                        {
                            // 从base_table中选择两个字节，组合生成新的变换
                            int idx1 = (int)((c + (ulong)i) % (ulong)baseSize);
                            int idx2 = (int)((d + (ulong)i) % (ulong)baseSize);
                            
                            // 组合两个字节创建新的变换规则
                            byte value = (byte)((table[idx1] + table[idx2]) % 256);
                            extraTable.Add(value);
                        }
                        
                        // 合并基础table和扩展部分
                        var extendedTable = table.Concat(extraTable).ToArray();
                        
                        // 为扩展表创建解密表
                        var baseTable = extendedTable.Take(baseSize).ToArray(); // 基础部分(0-255)
                        var extraTableArray = extraTable.ToArray(); // 扩展部分(256-383)
                        
                        // 创建基础解密表
                        var decryptTable = new byte[extendedSize];
                        
                        // 填充基础解密表
                        for (int i = 0; i < baseSize; i++)
                        {
                            decryptTable[baseTable[i]] = (byte)i;
                        }
                        
                        // 扩展部分的解密映射（在实际解密中不会用到，但为了完整性）
                        for (int i = 0; i < extraTableArray.Length; i++)
                        {
                            decryptTable[baseSize + i] = 0; // 不会用于解密
                        }
                        
                        var result = Tuple.Create(extendedTable, decryptTable);
                        _cachedTables[keyStr] = result;
                        return result;
                    }
                }
            }
        }
    }
}
