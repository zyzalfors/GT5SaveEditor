using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

    public class PFDHeader {
        public ulong magic;
        public ulong version;
    }

    public class PFDSignature {
        public byte[] bottom_hash;
        public byte[] top_hash;
        public byte[] hash_key;
        public byte[] padding;
        public byte[] Buffer {
            get {
                var data = new byte[64];
                Array.Copy(this.bottom_hash, 0, data, 0, 20);
                Array.Copy(this.top_hash, 0, data, 20, 20);
                Array.Copy(this.hash_key, 0, data, 40, 20);
                Array.Copy(this.padding, 0, data, 60, 4);
                return data;
            }
        }
    }

    public class PFDHashTable {
        public ulong capacity;
        public ulong num_reserved;
        public ulong num_used;
        public List<ulong> entries;
        public byte[] Buffer {
            get {
                var ms = new MemoryStream();
                using(var bw = new BinaryWriter(ms)) {
                    bw.Write(PS3Crypto.SwapByteOrder(this.capacity));
                    bw.Write(PS3Crypto.SwapByteOrder(this.num_reserved));
                    bw.Write(PS3Crypto.SwapByteOrder(this.num_used));
                    foreach(var value in this.entries) bw.Write(PS3Crypto.SwapByteOrder(value));
                }
                return ms.ToArray();
            }
        }
    }

    public class PFDEntry {
        public ulong addition_entry;
        public string file_name;
        public byte[] padding_0;
        public byte[] key;
        public List<byte[]> file_hashes;
        public byte[] padding_1;
        public ulong file_size;
        public byte[] Buffer {
            get {
                var ms = new MemoryStream();
                using(var bw = new BinaryWriter(ms)) {
                    bw.Write(PS3Crypto.SwapByteOrder(this.addition_entry));
                    var name = new byte[65];
                    Array.Copy(Encoding.ASCII.GetBytes(this.file_name), 0, name, 0, this.file_name.Length);
                    bw.Write(name, 0, name.Length);
                    bw.Write(this.padding_0, 0, this.padding_0.Length);
                    bw.Write(this.key, 0, this.key.Length);
                    foreach(var file_hash in this.file_hashes) bw.Write(file_hash, 0, file_hash.Length);
                    bw.Write(this.padding_1, 0, this.padding_1.Length);
                    bw.Write(PS3Crypto.SwapByteOrder(this.file_size));
                }
                return ms.ToArray();
            }
        }
        public byte[] BufferForHash {
            get {
                var ms = new MemoryStream();
                using(var bw = new BinaryWriter(ms)) {
                    var name = new byte[65];
                    Array.Copy(Encoding.ASCII.GetBytes(this.file_name), 0, name, 0, this.file_name.Length);
                    bw.Write(name, 0, name.Length);
                    bw.Write(this.key, 0, this.key.Length);
                    foreach(var file_hash in this.file_hashes) bw.Write(file_hash, 0, file_hash.Length);
                    bw.Write(this.padding_1, 0, this.padding_1.Length);
                    bw.Write(PS3Crypto.SwapByteOrder(this.file_size));
                }
                return ms.ToArray();
            }
        }
    }

    public class PFDEntrySignatureTable {
        public List<byte[]> hashes;
        public byte[] Buffer {
            get {
                var buffer = new byte[this.hashes.Count * 20];
                for(int i = 0; i < this.hashes.Count; i++) Array.Copy(this.hashes[i], 0, buffer, i * 20, 20);
                return buffer;
            }
        }
    }

    public class ParamPFD {
        private string root;
        private byte[] hash_secure_file_id;
        private byte[] real_key;
        private byte[] pfd_header_iv;
        private PFDHeader pfd_header;
        private PFDSignature pfd_signature;
        private PFDHashTable pfd_hash_table;
        private List<PFDEntry> pfd_entries;
        private PFDEntrySignatureTable pfd_signature_table;

        public ParamPFD(string root, string securefileid) {
            this.root = root;
            this.hash_secure_file_id = this.GenerateHashKeyForSecureFileID(PS3Crypto.StringToByteArray(securefileid));
            var path = Path.Combine(root, "PARAM.PFD");
            using(var br = new BinaryReader(new FileStream(path, FileMode.Open, FileAccess.Read))) {
                this.pfd_header = new PFDHeader {
                    magic = PS3Crypto.SwapByteOrder(br.ReadUInt64()),
                    version = PS3Crypto.SwapByteOrder(br.ReadUInt64())
                };
                if(this.pfd_header.magic != (ulong) 0x50464442) throw new Exception("Invalid PFD file");
                if(this.pfd_header.version != 3 && this.pfd_header.version != 4) throw new Exception("Unsupported PFD version");
                this.pfd_header_iv = br.ReadBytes(16);
                var decryptedHeader = PS3Crypto.DecryptWithPortability(this.pfd_header_iv, br.ReadBytes(64));
                this.pfd_signature = new PFDSignature {
                    bottom_hash = new byte[20],
                    top_hash = new byte[20],
                    hash_key = new byte[20],
                    padding = new byte[4]
                };
                Array.Copy(decryptedHeader, 0, this.pfd_signature.bottom_hash, 0, 20);
                Array.Copy(decryptedHeader, 20, this.pfd_signature.top_hash, 0, 20);
                Array.Copy(decryptedHeader, 40, this.pfd_signature.hash_key, 0, 20);
                Array.Copy(decryptedHeader, 60, this.pfd_signature.padding, 0, 4);
                if(this.pfd_header.version == 3) this.real_key = this.pfd_signature.hash_key;
                else this.real_key = PS3Crypto.GetHMACSHA1(PS3Crypto.GetStaticKey("keygen_key"), this.pfd_signature.hash_key);
                this.pfd_hash_table = new PFDHashTable {
                    capacity = PS3Crypto.SwapByteOrder(br.ReadUInt64()),
                    num_reserved = PS3Crypto.SwapByteOrder(br.ReadUInt64()),
                    num_used = PS3Crypto.SwapByteOrder(br.ReadUInt64()),
                    entries = new List<ulong>()
                };
                for(ulong i = 0; i < this.pfd_hash_table.capacity; i++) this.pfd_hash_table.entries.Add(PS3Crypto.SwapByteOrder(br.ReadUInt64()));
                this.pfd_entries = new List<PFDEntry>();
                for(ulong i = 0; i < this.pfd_hash_table.num_used; i++) {
                    var entry = new PFDEntry {
                        addition_entry = PS3Crypto.SwapByteOrder(br.ReadUInt64()),
                        file_name = Encoding.ASCII.GetString(br.ReadBytes(65)).Replace("\0", ""),
                        padding_0 = br.ReadBytes(7),
                        key = br.ReadBytes(64),
                        file_hashes = new List<byte[]>()
                    };
                    for(int j = 0; j < 4; j++) entry.file_hashes.Add(br.ReadBytes(20));
                    entry.padding_1 = br.ReadBytes(40);
                    entry.file_size = PS3Crypto.SwapByteOrder(br.ReadUInt64());
                    this.pfd_entries.Add(entry);
                }
                br.BaseStream.Position = (long) ((ulong) br.BaseStream.Position + 0x110 * (this.pfd_hash_table.num_reserved - this.pfd_hash_table.num_used));
                this.pfd_signature_table = new PFDEntrySignatureTable {
                    hashes = new List<byte[]>()
                };
                for(ulong i = 0; i < this.pfd_hash_table.capacity; i++) this.pfd_signature_table.hashes.Add(br.ReadBytes(20));
            }
        }

        private byte[] GenerateHashKeyForSecureFileID(byte[] securefileid) {
            if(securefileid.Length != 16) throw new Exception("SecureFileID must be 16 bytes in length");
            var key = new byte[20];
            Array.Copy(securefileid, 0, key, 0, 16);
            for(int i = 0, j = 0; i < key.Length; i++) {
                switch(i) {
                    case 1:
                        key[i] = 11;
                        break;
                    case 2:
                        key[i] = 15;
                        break;
                    case 5:
                        key[i] = 14;
                        break;
                    case 8:
                        key[i] = 10;
                        break;
                    default:
                        key[i] = securefileid[j++];
                        break;
                }
            }
            return key;
        }

        private byte[] GetEntryKey(PFDEntry entry) {
            var iv = this.hash_secure_file_id;
            return PS3Crypto.DecryptWithPortability(iv, entry.key);
        }

        public void DecryptAllFiles() {
            foreach(var entry in this.pfd_entries) {
                if(entry.file_name.ToUpper() == "PARAM.SFO") continue;
                var filepath = Path.Combine(this.root, entry.file_name);
                if(File.Exists(filepath)) DecryptFile(filepath, entry);
            }
        }

        private void DecryptFile(string filepath, PFDEntry entry) {
            byte[] data = File.ReadAllBytes(filepath);
            var key = GetEntryKey(entry);
            byte[] decData = PS3Crypto.Decrypt(key, data);
            File.WriteAllBytes(filepath, decData);
        }

        public void EncryptAllFiles() {
            foreach(var entry in this.pfd_entries) {
                if(entry.file_name.ToUpper() == "PARAM.SFO") continue;
                var filepath = Path.Combine(this.root, entry.file_name);
                if(File.Exists(filepath)) EncryptFile(filepath, entry);
            }
        }

        private void EncryptFile(string filepath, PFDEntry entry) {
            byte[] data = File.ReadAllBytes(filepath);
            var key = GetEntryKey(entry);
            byte[] encData = PS3Crypto.Encrypt(key, data);
            File.WriteAllBytes(filepath, encData);
        }

        private void UpdatePFDEntries() {
            foreach(var entry in this.pfd_entries) {
                if(entry.file_name.ToUpper() == "PARAM.SFO") continue;
                string filepath = Path.Combine(this.root, entry.file_name);
                var key = this.hash_secure_file_id;
                var hash = PS3Crypto.GetFileHMACSHA1(filepath, key);
                entry.file_hashes[0] = hash;
            }
        }

        private void UpdatePFDSignature() {
            this.pfd_signature.bottom_hash = PS3Crypto.GetHMACSHA1(this.real_key, this.pfd_signature_table.Buffer);
            this.pfd_signature.top_hash = PS3Crypto.GetHMACSHA1(this.real_key, this.pfd_hash_table.Buffer);
        }

        private ulong CalculateSignatureTableEntryIndex(string name) {
            ulong hash = 0;
            for(int i = 0; i < name.Length; i++) hash = (hash << 5) - hash + (byte) name[i];
            return hash % this.pfd_hash_table.capacity;
        }

        private void UpdatePFDEntrySignatureTable() {
            foreach(var entry in this.pfd_entries) {
                var signIndex = (int) CalculateSignatureTableEntryIndex(entry.file_name);
                var pfdIndex = this.pfd_hash_table.entries[signIndex];
                var sha1 = new HMACSHA1(this.real_key);
                var hashdata = new List<byte>();
                while(pfdIndex < this.pfd_hash_table.num_reserved) {
                    PFDEntry ent = this.pfd_entries[(int) pfdIndex];
                    var buffer = ent.BufferForHash;
                    hashdata.AddRange(buffer);
                    pfdIndex = ent.addition_entry;
                }
                sha1.ComputeHash(hashdata.ToArray());
                this.pfd_signature_table.hashes[signIndex] = sha1.Hash;
            }
        }

        public void RebuilParamPFD() {
            EncryptAllFiles();
            UpdatePFDEntries();
            UpdatePFDEntrySignatureTable();
            UpdatePFDSignature();
            WriteParamPFD();
        }

        private void WriteParamPFD() {
            var ms = new MemoryStream();
            using(var bw = new BinaryWriter(ms)) {
                bw.Write(PS3Crypto.SwapByteOrder(this.pfd_header.magic));
                bw.Write(PS3Crypto.SwapByteOrder(this.pfd_header.version));
                bw.Write(this.pfd_header_iv, 0, this.pfd_header_iv.Length);
                var buffer = PS3Crypto.EncryptWithPortability(this.pfd_header_iv, this.pfd_signature.Buffer);
                bw.Write(buffer, 0, buffer.Length);
                buffer = this.pfd_hash_table.Buffer;
                bw.Write(buffer, 0, buffer.Length);
                foreach(var entry in this.pfd_entries) {
                  buffer = entry.Buffer;
                  bw.Write(buffer, 0, buffer.Length);
                }
                buffer = new byte[0x110 * (this.pfd_hash_table.num_reserved - this.pfd_hash_table.num_used)];
                bw.Write(buffer, 0, buffer.Length);
                buffer = this.pfd_signature_table.Buffer;
                bw.Write(buffer, 0, buffer.Length);
                buffer = new byte[0x8000 - ms.Length];
                if(buffer.Length > 0) bw.Write(buffer, 0, buffer.Length);
            }
            var path = Path.Combine(this.root, "PARAM.PFD");
            File.WriteAllBytes(path, ms.ToArray());
        }

    }
