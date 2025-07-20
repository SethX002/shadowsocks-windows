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
        private static readonly string[] USER_AGENTS = new string[]
        {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        };
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
        // HTTP 状态码和对应的文本
        private static readonly Dictionary<int, string> STATUS_TEXTS = new Dictionary<int, string>
        {
            { 200, "OK" },
            { 301, "Moved Permanently" },
            { 302, "Found" },
            { 304, "Not Modified" },
            { 307, "Temporary Redirect" },
            { 404, "Not Found" }
        };
        // 常用的状态码，大多数是200
        private static readonly int[] STATUS_CODES = new int[] { 200, 200, 200, 200, 200, 301, 302, 304, 307, 404 };

        public HttpMixEncryptor(string method, string password) : base(method, password)
        {
            _opEncrypt = true; // default to encrypt
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
            // Use MD5 as in Python code
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        #region TCP
        public override void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // Encrypt and add HTTP header if not already
            var data = new byte[length];
            Buffer.BlockCopy(buf, 0, data, 0, length);
            var encrypted = _cipher.Encrypt(data);
            if (!_haveHeader)
            {
                // 随机决定是生成HTTP请求头还是响应头
                var rand = new Random();
                byte[] header;
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
            // Buffer until header is removed
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
            Encrypt(buf, length, outbuf, out outlength);
        }

        public override void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            Decrypt(buf, length, outbuf, out outlength);
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

        // Helper: find index of byte pattern
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

        // HTTP请求头生成
        private static byte[] GenerateHttpRequestHeader(int dataLen)
        {
            var rand = new Random();
            string domain = COMMON_DOMAINS[rand.Next(COMMON_DOMAINS.Length)];
            string path = COMMON_PATHS[rand.Next(COMMON_PATHS.Length)];
            string userAgent = USER_AGENTS[rand.Next(USER_AGENTS.Length)];
            string requestId = string.Concat(Enumerable.Range(0, 32).Select(_ => rand.Next(16).ToString("x")));
            var headers = new List<string>
            {
                $"GET {path} HTTP/1.1",
                $"Host: {domain}",
                $"User-Agent: {userAgent}",
                $"X-Request-ID: {requestId}"
            };
            int extraHeadersCount = rand.Next(2, 6);
            headers.AddRange(HTTP_HEADERS.OrderBy(_ => rand.Next()).Take(extraHeadersCount));
            headers.Add($"Content-Length: {dataLen}");
            headers.Add("");
            headers.Add("");
            return Encoding.UTF8.GetBytes(string.Join("\r\n", headers));
        }

        // HTTP响应头生成
        private static byte[] GenerateHttpResponseHeader(int dataLen)
        {
            var rand = new Random();
            // 随机选择HTTP状态码，大多数是200
            int status = STATUS_CODES[rand.Next(STATUS_CODES.Length)];
            string statusText = STATUS_TEXTS[status];
            
            var headers = new List<string>
            {
                $"HTTP/1.1 {status} {statusText}",
                $"Date: {DateTime.UtcNow.ToString("r")}",
                "Server: nginx/1.18.0",
                "Content-Type: text/html; charset=utf-8",
                $"Content-Length: {dataLen}",
                "Connection: keep-alive"
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
            
            headers.Add("");
            headers.Add("");
            
            return Encoding.UTF8.GetBytes(string.Join("\r\n", headers));
        }

        // --- ExtendedTableCipher inner class ---
        private class ExtendedTableCipher
        {
            private byte[] _encryptTable;
            private byte[] _decryptTable;
            private bool _opEncrypt;
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
                    for (int i = 0; i < data.Length; i++)
                    {
                        byte b = data[i];
                        if (b < 256)
                            result[i] = _encryptTable[b];
                        else
                            result[i] = b;
                    }
                }
                else
                {
                    for (int i = 0; i < data.Length; i++)
                    {
                        byte b = data[i];
                        if (b < 256)
                            result[i] = _decryptTable[b];
                        else
                            result[i] = b;
                    }
                }
                return result;
            }
            // Table generation logic
            private static Tuple<byte[], byte[]> InitExtendedTable(byte[] key)
            {
                // MD5 hash
                using (var md5 = MD5.Create())
                {
                    var s = md5.ComputeHash(key);
                    ulong a = BitConverter.ToUInt64(s, 0);
                    ulong b = BitConverter.ToUInt64(s, 8);
                    int baseSize = 256;
                    int extendedSize = baseSize + baseSize / 2;
                    var table = Enumerable.Range(0, baseSize).Select(i => (byte)i).ToArray();
                    // Sort table
                    for (int i = 1; i < 1024; i++)
                    {
                        table = table.OrderBy(x => (int)(a % (ulong)(x + i))).ToArray();
                    }
                    // Extra table
                    using (var sha256 = SHA256.Create())
                    {
                        sha256.TransformBlock(key, 0, key.Length, null, 0);
                        sha256.TransformFinalBlock(s, 0, s.Length);
                        var extraSeed = sha256.Hash;
                        ulong c = BitConverter.ToUInt64(extraSeed, 0);
                        ulong d = BitConverter.ToUInt64(extraSeed, 8);
                        var extraTable = new List<byte>();
                        for (int i = 0; i < baseSize / 2; i++)
                        {
                            int idx1 = (int)((c + (ulong)i) % (ulong)baseSize);
                            int idx2 = (int)((d + (ulong)i) % (ulong)baseSize);
                            byte value = (byte)(((int)table[idx1] + (int)table[idx2]) % 256);
                            extraTable.Add(value);
                        }
                        var extendedTable = table.Concat(extraTable).ToArray();
                        // Decrypt table
                        var decryptTable = new byte[extendedTable.Length];
                        for (int i = 0; i < baseSize; i++)
                        {
                            decryptTable[extendedTable[i]] = (byte)i;
                        }
                        for (int i = 0; i < extraTable.Count; i++)
                        {
                            decryptTable[baseSize + i] = (byte)0; // Not used in decryption
                        }
                        return Tuple.Create(extendedTable, decryptTable);
                    }
                }
            }
        }
    }
}
