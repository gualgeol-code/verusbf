from bitcoin import *
import argparse
import threading
import queue
import sys
import os
import hashlib
import base58
import random
import hmac
from hashlib import blake2b, sha256, sha512
import binascii
import secrets
import unicodedata
import csv
from datetime import datetime
import time

# Untuk tabel output
TABULATE_AVAILABLE = False
try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

# Karakter valid untuk Verus Coin address (Base58)
VALID_CHARS = set('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')

# Verus Coin specific constants
VRSC_PUBKEY_ADDRESS = 0x3C
VRSC_SCRIPT_ADDRESS = 0x55
VRSC_SECRET_KEY = 0xBC

# BIP39 constants untuk Verus
PBKDF2_ROUNDS = 2048

def load_verus_wordlist(file_path="bipverusseed.txt"):
    """Memuat wordlist Verus dari file"""
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"✅ Loaded {len(words)} words from Verus wordlist")
        return words
    except FileNotFoundError:
        print(f"❌ Error: File '{file_path}' tidak ditemukan.")
        sys.exit(1)

def verus_entropy_to_mnemonic(entropy, wordlist):
    """Convert entropy to Verus mnemonic phrase"""
    entropy_bytes = entropy
    entropy_length = len(entropy_bytes) * 8
    
    hash_bytes = hashlib.sha256(entropy_bytes).digest()
    checksum_length = entropy_length // 32
    checksum_bits = bin(int.from_bytes(hash_bytes, 'big'))[2:].zfill(256)[:checksum_length]
    
    entropy_bits = bin(int.from_bytes(entropy_bytes, 'big'))[2:].zfill(entropy_length)
    combined_bits = entropy_bits + checksum_bits
    
    chunks = [combined_bits[i:i+11] for i in range(0, len(combined_bits), 11)]
    
    indices = [int(chunk, 2) % len(wordlist) for chunk in chunks]
    
    return ' '.join([wordlist[idx] for idx in indices])

def mnemonic_to_seed(mnemonic, passphrase=""):
    """Convert mnemonic to seed menggunakan PBKDF2-HMAC-SHA512"""
    mnemonic_normalized = unicodedata.normalize("NFKD", mnemonic)
    passphrase_normalized = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    
    seed = hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic_normalized.encode("utf-8"),
        passphrase_normalized.encode("utf-8"),
        PBKDF2_ROUNDS,
        64
    )
    
    return seed

def seed_to_private_key(seed, index=0):
    """Convert seed to private key"""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    IL = I[:32]
    private_key_hex = binascii.hexlify(IL).decode('utf-8')
    
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    priv_int = int(private_key_hex, 16)
    
    if priv_int == 0 or priv_int >= n:
        return seed_to_private_key(seed, index + 1)
    
    return private_key_hex, I[32:]

def verus_pubkey_to_address(pubkey_hex):
    """Convert public key to Verus Coin address"""
    sha256_1 = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
    blake2b_hash = blake2b(sha256_1, digest_size=20).digest()
    
    network_byte = bytes([VRSC_PUBKEY_ADDRESS])
    hashed = network_byte + blake2b_hash
    
    sha256_2 = hashlib.sha256(hashed).digest()
    sha256_3 = hashlib.sha256(sha256_2).digest()
    checksum = sha256_3[:4]
    
    address_bytes = hashed + checksum
    return base58.b58encode(address_bytes).decode('utf-8')

def generate_keys_from_mnemonic(mnemonic, passphrase="", index=0):
    """Generate Verus keys from mnemonic"""
    seed = mnemonic_to_seed(mnemonic, passphrase)
    priv_hex, chain_code = seed_to_private_key(seed, index)
    pub = privkey_to_pubkey(priv_hex)
    pub_compressed = compress(pub)
    addr = verus_pubkey_to_address(pub_compressed)
    
    return priv_hex, pub_compressed, addr, mnemonic, seed.hex()

def generate_random_mnemonic_keys(wordlist):
    """Generate random Verus mnemonic and derive keys"""
    word_counts = [12, 15, 18, 21, 24]
    word_count = random.choice(word_counts)
    
    entropy_bits_per_word = 11
    total_bits = word_count * entropy_bits_per_word
    checksum_bits = total_bits // 33
    entropy_bits = total_bits - checksum_bits
    
    entropy_bytes = secrets.token_bytes(entropy_bits // 8)
    mnemonic = verus_entropy_to_mnemonic(entropy_bytes, wordlist)
    
    return generate_keys_from_mnemonic(mnemonic)

def generate_verus_keys_traditional():
    """Generate keys menggunakan metode tradisional"""
    priv = random_key()
    pub = privkey_to_pubkey(priv)
    pub_compressed = compress(pub)
    addr = verus_pubkey_to_address(pub_compressed)
    
    return priv, pub_compressed, addr, "", ""

class ProgressBar:
    """Simple progress bar untuk multi-threading"""
    
    def __init__(self, total=0, description="Progress"):
        self.total = total
        self.description = description
        self.current = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.last_update = 0
        self.update_interval = 0.1
    
    def update(self, n=1):
        """Update progress"""
        with self.lock:
            self.current += n
            current_time = time.time()
            
            if current_time - self.last_update >= self.update_interval:
                self._display()
                self.last_update = current_time
    
    def _display(self):
        """Display progress bar"""
        if self.total > 0:
            percent = (self.current / self.total) * 100
            bar_length = 40
            filled_length = int(bar_length * self.current // self.total)
            bar = '█' * filled_length + '░' * (bar_length - filled_length)
            
            elapsed = time.time() - self.start_time
            speed = self.current / elapsed if elapsed > 0 else 0
            
            if self.current < self.total:
                print(f"\r{self.description}: |{bar}| {percent:.1f}% ({self.current:,}/{self.total:,}) | "
                      f"Speed: {speed:.1f}/s | ETA: {self._calculate_eta():.0f}s", end="", flush=True)
            else:
                print(f"\r{self.description}: |{bar}| 100.0% ({self.current:,}/{self.total:,}) | "
                      f"Completed in {elapsed:.1f}s", end="", flush=True)
        else:
            elapsed = time.time() - self.start_time
            speed = self.current / elapsed if elapsed > 0 else 0
            print(f"\r{self.description}: {self.current:,} addresses | "
                  f"Speed: {speed:.1f}/s | Time: {elapsed:.1f}s", end="", flush=True)
    
    def _calculate_eta(self):
        """Calculate ETA"""
        if self.current == 0:
            return 0
        elapsed = time.time() - self.start_time
        return (elapsed / self.current) * (self.total - self.current)
    
    def close(self):
        """Close progress bar dengan newline"""
        print()

class VerusAddressGenerator:
    """Class utama untuk generate Verus addresses"""
    
    def __init__(self, config):
        self.config = config
        self.stop_event = threading.Event()
        self.results_queue = queue.Queue()
        self.start_time = None
        
        # Progress tracker
        self.progress_bar = ProgressBar(
            total=config.get('max_finds', 0),
            description="Generating addresses"
        )
        
        # File output
        self.output_txt = config['output_file']
        self.csv_filename = self.output_txt.replace('.txt', '.csv') if self.output_txt.endswith('.txt') else self.output_txt + '.csv'
        
        # CSV writer
        self.csv_file = None
        self.csv_writer = None
        
        # Counters
        self.addresses_generated = 0
        self.counter_lock = threading.Lock()
        
        # Results storage
        self.all_results = []
    
    def init_csv_file(self):
        """Initialize CSV file"""
        try:
            self.csv_file = open(self.csv_filename, 'w', newline='', encoding='utf-8')
            self.csv_writer = csv.writer(self.csv_file)
            self.csv_writer.writerow(['Address', 'Private_Key', 'Public_Key', 'Mnemonic', 'Seed', 'Timestamp'])
            
            print(f"💾 Output files:")
            print(f"   • {self.output_txt} (summary)")
            print(f"   • {self.csv_filename} (all addresses)")
            print()
            
            return True
        except Exception as e:
            print(f"❌ Error initializing CSV file: {e}")
            return False
    
    def save_to_csv(self, address, priv_key, pub_key, mnemonic, seed):
        """Simpan hasil ke CSV"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            row = [address, priv_key, pub_key, mnemonic, seed, timestamp]
            self.csv_writer.writerow(row)
            self.csv_file.flush()
            return True
        except:
            return False
    
    def worker_thread(self, thread_id):
        """Thread worker untuk generate address"""
        while not self.stop_event.is_set():
            # Cek jika sudah mencapai target
            if self.config['max_finds'] > 0 and self.addresses_generated >= self.config['max_finds']:
                break
            
            try:
                # Generate key pair
                if self.config['use_mnemonic']:
                    priv_hex, pub_compressed, addr, mnemonic, seed_hex = generate_random_mnemonic_keys(self.config['wordlist'])
                else:
                    priv_hex, pub_compressed, addr, mnemonic, seed_hex = generate_verus_keys_traditional()
                
                # Hanya proses address yang valid (dimulai dengan 'R')
                if not addr.startswith('R'):
                    continue
                
                # Update counter
                with self.counter_lock:
                    self.addresses_generated += 1
                    current_count = self.addresses_generated
                
                # Update progress bar
                self.progress_bar.update(1)
                
                # Buat result object
                result = {
                    'address': addr,
                    'private_key': priv_hex,
                    'public_key': pub_compressed,
                    'mnemonic': mnemonic,
                    'seed': seed_hex,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # Simpan ke queue
                self.results_queue.put(result)
                
                # Hentikan jika mencapai target
                if self.config['max_finds'] > 0 and current_count >= self.config['max_finds']:
                    self.stop_event.set()
                    break
                    
            except Exception as e:
                if not self.stop_event.is_set():
                    print(f"\n⚠️ Thread {thread_id} error: {e}")
    
    def process_results(self):
        """Proses hasil dari queue dan simpan ke CSV"""
        while not self.stop_event.is_set() or not self.results_queue.empty():
            try:
                result = self.results_queue.get(timeout=0.5)
                
                # Simpan ke semua results
                self.all_results.append(result)
                
                # Simpan ke CSV
                if self.csv_writer:
                    self.save_to_csv(
                        result['address'],
                        result['private_key'],
                        result['public_key'],
                        result['mnemonic'],
                        result['seed']
                    )
                
                self.results_queue.task_done()
                
            except queue.Empty:
                continue
    
    def run(self):
        """Jalankan generate process"""
        self.start_time = time.time()
        
        # Initialize CSV file
        if not self.init_csv_file():
            print("⚠️  Continuing without CSV file...")
        
        # Display startup info
        print(f"🚀 Starting {self.config['nthreads']} threads...")
        if self.config['max_finds'] > 0:
            print(f"🎯 Target: {self.config['max_finds']:,} addresses")
        else:
            print("🎯 Target: Unlimited (press Ctrl+C to stop)")
        print(f"🔧 Method: {'Mnemonic' if self.config['use_mnemonic'] else 'Traditional'}")
        print("-" * 60)
        
        # Buat worker threads
        worker_threads = []
        for i in range(self.config['nthreads']):
            thread = threading.Thread(target=self.worker_thread, args=(i+1,), daemon=True)
            worker_threads.append(thread)
            thread.start()
        
        # Thread untuk memproses hasil
        processor_thread = threading.Thread(target=self.process_results, daemon=True)
        processor_thread.start()
        
        try:
            # Tampilkan progress bar
            print()
            self.progress_bar._display()
            
            # Tunggu semua worker threads selesai
            while any(t.is_alive() for t in worker_threads) and not self.stop_event.is_set():
                # Update progress bar secara periodic
                self.progress_bar._display()
                time.sleep(0.2)
                
                # Cek jika semua selesai
                if self.config['max_finds'] > 0 and self.addresses_generated >= self.config['max_finds']:
                    self.stop_event.set()
                    break
            
            # Tunggu processor thread selesai
            self.results_queue.join()
            processor_thread.join(timeout=2)
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Stopped by user...")
            self.stop_event.set()
        
        finally:
            # Close progress bar
            self.progress_bar.close()
            
            # Tunggu semua threads
            for thread in worker_threads:
                thread.join(timeout=1)
            
            # Save summary
            self.save_summary()
            
            # Display final results
            self.display_final_results()
            
            # Close CSV file
            if self.csv_file:
                self.csv_file.close()
    
    def save_summary(self):
        """Simpan summary ke file .txt"""
        try:
            elapsed = time.time() - self.start_time
            speed = self.addresses_generated / elapsed if elapsed > 0 else 0
            
            with open(self.output_txt, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("VERUS COIN ADDRESS GENERATOR - SUMMARY REPORT\n")
                f.write("="*80 + "\n\n")
                
                f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total addresses generated: {self.addresses_generated:,}\n")
                f.write(f"Total time: {elapsed:.1f} seconds\n")
                f.write(f"Average speed: {speed:.1f} addresses/second\n")
                f.write(f"Generation method: {'Mnemonic' if self.config['use_mnemonic'] else 'Traditional'}\n")
                f.write(f"Threads used: {self.config['nthreads']}\n\n")
                
                # Tampilkan sample addresses
                sample_size = min(20, len(self.all_results))
                if sample_size > 0:
                    f.write(f"SAMPLE ADDRESSES (showing {sample_size} of {len(self.all_results)}):\n")
                    f.write("-"*80 + "\n")
                    
                    headers = ["No", "Address", "Private Key (truncated)", "Method"]
                    table_data = []
                    
                    for idx, result in enumerate(self.all_results[:sample_size], 1):
                        priv_key = result['private_key']
                        if len(priv_key) > 16:
                            priv_key = priv_key[:8] + "..." + priv_key[-8:]
                        
                        method = "Mnemonic" if result['mnemonic'] else "Traditional"
                        
                        row = [
                            idx,
                            result['address'],
                            priv_key,
                            method
                        ]
                        table_data.append(row)
                    
                    if TABULATE_AVAILABLE:
                        table = tabulate(table_data, headers=headers, tablefmt="grid")
                        f.write(table + "\n")
                    else:
                        for row in table_data:
                            f.write(f"{row[0]:>3}. {row[1]:40} {row[2]:30} {row[3]:12}\n")
                else:
                    f.write("No addresses generated.\n")
                
                f.write("\n" + "="*80 + "\n")
                f.write("FILES GENERATED:\n")
                f.write(f"1. {self.output_txt} (this summary file)\n")
                f.write(f"2. {self.csv_filename} (CSV with all addresses)\n")
                f.write("="*80 + "\n")
            
            print(f"✅ Summary saved to: {self.output_txt}")
            
        except Exception as e:
            print(f"❌ Error saving summary: {e}")
    
    def display_final_results(self):
        """Tampilkan hasil akhir"""
        elapsed = time.time() - self.start_time
        speed = self.addresses_generated / elapsed if elapsed > 0 else 0
        
        print("\n" + "="*80)
        print("📊 FINAL RESULTS")
        print("="*80)
        print(f"⏱️  Total Time: {elapsed:.1f} seconds")
        print(f"🔢 Addresses Generated: {self.addresses_generated:,}")
        print(f"⚡ Average Speed: {speed:.1f} addresses/second")
        print(f"🔧 Method: {'Mnemonic' if self.config['use_mnemonic'] else 'Traditional'}")
        
        # Tampilkan sample addresses
        if self.all_results:
            sample_size = min(10, len(self.all_results))
            print(f"\n📋 Showing {sample_size} sample addresses:")
            print("-" * 80)
            
            if TABULATE_AVAILABLE:
                headers = ["No", "Address", "Private Key", "Method"]
                table_data = []
                
                for idx, result in enumerate(self.all_results[:sample_size], 1):
                    priv_key = result['private_key']
                    if len(priv_key) > 20:
                        priv_key = priv_key[:10] + "..." + priv_key[-10:]
                    
                    method = "Mnemonic" if result['mnemonic'] else "Traditional"
                    
                    table_data.append([idx, result['address'], priv_key, method])
                
                table = tabulate(table_data, headers=headers, tablefmt="grid")
                print("\n" + table)
            else:
                print("No. Address                                    Private Key                     Method")
                print("-" * 80)
                for idx, result in enumerate(self.all_results[:sample_size], 1):
                    priv_key = result['private_key']
                    if len(priv_key) > 20:
                        priv_key = priv_key[:10] + "..." + priv_key[-10:]
                    
                    method = "Mnemonic" if result['mnemonic'] else "Traditional"
                    print(f"{idx:>3}. {result['address']:40} {priv_key:30} {method:12}")
        
        print("\n" + "="*80)
        print("💾 FILES GENERATED:")
        print(f"   • {self.output_txt} (summary)")
        print(f"   • {self.csv_filename} (all addresses in CSV format)")
        print("="*80)

def main():
    """Fungsi utama"""
    parser = argparse.ArgumentParser(
        description='Verus Coin Address Generator (No Balance Check)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Generate 1000 addresses:
    python verus_address_generator.py -t 8 --max 1000
  
  Generate unlimited addresses:
    python verus_address_generator.py -t 8
  
  Use traditional method (no mnemonic):
    python verus_address_generator.py -t 8 --max 5000 --no-mnemonic
        """
    )
    
    parser.add_argument('--wordlist', type=str, default='bipverusseed.txt',
                       help='Verus wordlist file (default: bipverusseed.txt)')
    
    parser.add_argument('-of', '--output', type=str, default='',
                       help='Output filename (default: auto-generated)')
    
    parser.add_argument('-t', '--threads', type=int, default=4,
                       help='Number of threads (default: 4)')
    
    parser.add_argument('--max', type=int, default=0,
                       help='Maximum addresses to generate (0 = unlimited)')
    
    parser.add_argument('--no-mnemonic', action='store_true',
                       help='Use traditional key generation instead of mnemonic')
    
    parser.add_argument('--prefix-file', type=str,
                       help='File containing address prefixes to filter (optional)')
    
    parser.add_argument('--case-sensitive', action='store_true',
                       help='Case sensitive prefix matching')
    
    args = parser.parse_args()
    
    # Validasi args
    if args.threads <= 0:
        print("❌ Error: Thread count must be > 0")
        sys.exit(1)
    
    if args.max < 0:
        print("❌ Error: Max finds cannot be negative")
        sys.exit(1)
    
    # Load wordlist
    wordlist = load_verus_wordlist(args.wordlist)
    
    # Set default output file
    if not args.output:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = f'verus_addresses_{timestamp}.txt'
    
    # Prepare config
    config = {
        'wordlist': wordlist,
        'output_file': args.output,
        'nthreads': args.threads,
        'max_finds': args.max,
        'use_mnemonic': not args.no_mnemonic,
        'prefix_file': args.prefix_file,
        'case_sensitive': args.case_sensitive
    }
    
    # Display banner
    banner = f"""
{'='*80}
🚀 VERUS COIN ADDRESS GENERATOR (No Balance Check)
{'='*80}
⚡ Threads: {args.threads} | Target: {'Unlimited' if args.max == 0 else f'{args.max:,}'}
🔧 Method: {'Mnemonic' if config['use_mnemonic'] else 'Traditional'}
💾 Output: {args.output}
{'='*80}
"""
    print(banner)
    
    try:
        generator = VerusAddressGenerator(config)
        generator.run()
    except KeyboardInterrupt:
        print("\n\n👋 Program stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
