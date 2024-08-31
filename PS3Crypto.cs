using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

    public static class PS3Crypto {

        public static readonly string[] StaticKeys = new string[]  {
            "syscon_manager_key=D413B89663E1FE9F75143D3BB4565274",
            "keygen_key=6B1ACEA246B745FD8F93763B920594CD53483B82"
        };

        public static ulong SwapByteOrder(ulong value) {
            return ((value & 0xff00000000000000L) >> 56) |
                   ((value & 0x00ff000000000000L) >> 40) |
                   ((value & 0x0000ff0000000000L) >> 24) |
                   ((value & 0x000000ff00000000L) >> 8) |
                   ((value & 0x00000000ff000000L) << 8) |
                   ((value & 0x0000000000ff0000L) << 24) |
                   ((value & 0x000000000000ff00L) << 40) |
                   ((value & 0x00000000000000ffL) << 56);
        }

        public static byte[] DecryptWithPortability(byte[] iv, byte[] data) {
            var x = new AesCryptoServiceProvider();
            x.Mode = CipherMode.CBC;
            x.Padding = PaddingMode.Zeros;
            var key = GetStaticKey("syscon_manager_key");
            if(iv.Length != 16) Array.Resize(ref iv, 16);
            return x.CreateDecryptor(key, iv).TransformFinalBlock(data, 0, data.Length);
        }

        public static byte[] EncryptWithPortability(byte[] iv, byte[] data) {
            var x = new AesCryptoServiceProvider();
            x.Mode = CipherMode.CBC;
            x.Padding = PaddingMode.Zeros;
            var key = GetStaticKey("syscon_manager_key");
            if(iv.Length != 16) Array.Resize(ref iv, 16);
            return x.CreateEncryptor(key, iv).TransformFinalBlock(data, 0, data.Length);
        }

        public static byte[] StringToByteArray(string hex) {
            if(hex == null) return null;
            if(hex.Length % 2 != 0) hex = hex.PadLeft(hex.Length + 1, '0');
            return Enumerable.Range(0, hex.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
        }

        public static byte[] GetStaticKey(string name) {
            foreach(var line in StaticKeys) {
                var x = line.Split('=')[0];
                if(x.ToLower() == name.ToLower()) {
                    var value = line.Split('=')[1];
                    return StringToByteArray(value);
                }
            }
            return null;
        }

        public static byte[] GetHMACSHA1(byte[] key, byte[] data) {
            return new HMACSHA1(key).ComputeHash(data, 0, data.Length);
        }

        public static byte[] GetFileHMACSHA1(string path, byte[] key) {
            return new HMACSHA1(key).ComputeHash(File.Open(path, FileMode.Open, FileAccess.Read));
        }

        public static byte[] Decrypt(byte[] key, byte[] input) {
            Array.Resize(ref key, 16);
            var x1 = Aes.Create();
            x1.Key = key;
            x1.BlockSize = 128;
            x1.Mode = CipherMode.ECB;
            x1.Padding = PaddingMode.Zeros;
            var x2 = Aes.Create();
            x2.Key = key;
            x1.BlockSize = 128;
            x2.Mode = CipherMode.ECB;
            x2.Padding = PaddingMode.Zeros;
            var numBlocks = input.Length / 16;
            var output = new byte[input.Length];
            for(int i = 0; i < numBlocks; i++) {
                var blockdata = new byte[16];
                Array.Copy(input, i * 16, blockdata, 0, 16);
                var counterKey = new byte[16];
                Array.Copy(BitConverter.GetBytes(SwapByteOrder((ulong) i)), 0, counterKey, 0, 8);
                counterKey = x1.CreateEncryptor().TransformFinalBlock(counterKey, 0, counterKey.Length);
                blockdata = x2.CreateDecryptor().TransformFinalBlock(blockdata, 0, blockdata.Length);
                for(int j = 0; j < 16; j++) blockdata[j] ^= counterKey[j];
                Array.Copy(blockdata, 0, output, i * 16, 16);
            }
            return output;
        }

        public static byte[] Encrypt(byte[] key, byte[] input) {
            Array.Resize(ref key, 16);
            var x1 = Aes.Create();
            x1.Key = key;
            x1.BlockSize = 128;
            x1.Mode = CipherMode.ECB;
            x1.Padding = PaddingMode.Zeros;
            var x2 = Aes.Create();
            x2.Key = key;
            x1.BlockSize = 128;
            x2.Mode = CipherMode.ECB;
            x2.Padding = PaddingMode.Zeros;
            var numBlocks = input.Length / 16;
            var output = new byte[input.Length];
            for(int i = 0; i < numBlocks; i++) {
                var blockdata = new byte[16];
                Array.Copy(input, i * 16, blockdata, 0, 16);
                var counterKey = new byte[16];
                Array.Copy(BitConverter.GetBytes(SwapByteOrder((ulong) i)), 0, counterKey, 0, 8);
                counterKey = x1.CreateEncryptor().TransformFinalBlock(counterKey, 0, counterKey.Length);
                for(int j = 0; j < 16; j++) blockdata[j] ^= counterKey[j];
                blockdata = x2.CreateEncryptor().TransformFinalBlock(blockdata, 0, blockdata.Length);
                Array.Copy(blockdata, 0, output, i * 16, 16);
            }
            return output;
        }
    }