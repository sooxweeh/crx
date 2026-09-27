#!/usr/bin/env python3
"""
=============================================================================
CRYPTOGRAPHIC ATTACK DEMONSTRATIONS - EDUCATIONAL ONLY
=============================================================================
WARNING: For authorized security testing and education only!
Never use these techniques on systems you don't own or have permission to test.
=============================================================================
Requirements: Python 3.7+ (uses only standard library - no pip install needed)
Run: python crypto_demo.py
=============================================================================
"""

import hashlib
import hmac
import os
import sys
import time
import random
import secrets
import struct
import binascii
import base64
from datetime import datetime


# ============================================================================
# COLOR SUPPORT FOR WINDOWS CMD
# ============================================================================

def enable_windows_ansi():
    """Enable ANSI colors in Windows CMD"""
    if sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


ANSI_OK = enable_windows_ansi()


class Colors:
    """ANSI color codes with Windows fallback"""
    if ANSI_OK:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
        DIM = '\033[2m'
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''
        BOLD = RESET = DIM = ''


def cprint(text, color='', bold=False, end='\n'):
    """Colored print helper"""
    prefix = (Colors.BOLD if bold else '') + color
    print(f"{prefix}{text}{Colors.RESET}", end=end)


def clear_screen():
    """Clear terminal screen cross-platform"""
    os.system('cls' if os.name == 'nt' else 'clear')


def pause(seconds=0.8):
    """Small pause for effect - low CPU"""
    time.sleep(seconds)


def section_header(number, title, subtitle=""):
    """Print a section header"""
    print()
    cprint("=" * 68, Colors.CYAN)
    cprint(f"  [{number}/8] {title}", Colors.CYAN, bold=True)
    if subtitle:
        cprint(f"  {subtitle}", Colors.DIM)
    cprint("=" * 68, Colors.CYAN)
    print()


def show_result(label, value, color=Colors.GREEN):
    """Show a labeled result"""
    print(f"  {Colors.BOLD}{label}:{Colors.RESET} {color}{value}{Colors.RESET}")


def show_warning(text):
    """Show warning message"""
    print(f"  {Colors.YELLOW}[!] {text}{Colors.RESET}")


def show_danger(text):
    """Show danger message"""
    print(f"  {Colors.RED}[X] {text}{Colors.RESET}")


def show_safe(text):
    """Show safe message"""
    print(f"  {Colors.GREEN}[✓] {text}{Colors.RESET}")


# ============================================================================
# DEMO 1: MD5 COLLISION CONCEPT
# ============================================================================

def demo_md5_collision():
    """Demonstrate MD5 collision concept (educational)"""
    section_header(1, "MD5 COLLISION CONCEPT",
                   "Why MD5 is cryptographically broken")
    
    cprint("  What we're doing:", Colors.WHITE, bold=True)
    print("  → Hashing two different inputs with MD5")
    print("  → Showing how MD5 was deprecated for security")
    print()
    
    # Two different inputs
    input1 = b"The quick brown fox jumps over the lazy dog"
    input2 = b"The quick brown fox jumps over the lazy cog"
    
    md5_1 = hashlib.md5(input1).hexdigest()
    md5_2 = hashlib.md5(input2).hexdigest()
    
    print(f"  Input 1:  {Colors.DIM}{input1.decode()[:50]}...{Colors.RESET}")
    show_result("MD5(1)", md5_1, Colors.MAGENTA)
    print()
    print(f"  Input 2:  {Colors.DIM}{input2.decode()[:50]}...{Colors.RESET}")
    show_result("MD5(2)", md5_2, Colors.MAGENTA)
    print()
    
    if md5_1 != md5_2:
        cprint("  Different inputs → Different hashes (this time)", Colors.WHITE)
    
    print()
    cprint("  CONCEPT:", Colors.YELLOW, bold=True)
    print("  MD5 is vulnerable to collision attacks. Two DIFFERENT inputs")
    print("  can produce the SAME hash. This breaks digital signatures,")
    print("  file integrity checks, and certificate validation.")
    print()
    show_danger("DO NOT USE MD5 for any security purpose!")
    show_safe("Use SHA-256 or SHA-3 instead")
    
    pause(1.2)


# ============================================================================
# DEMO 2: WEAK KEY GENERATION
# ============================================================================

def demo_weak_keys():
    """Show weak vs strong key generation"""
    section_header(2, "WEAK KEY GENERATION",
                   "Predictable seeds = predictable keys")
    
    print(f"  {Colors.RED}BAD:{Colors.RESET} Using random.seed() with fixed value")
    print()
    
    # Bad: predictable seed
    random.seed(12345)
    weak_key = random.getrandbits(128)
    show_result("Weak Key", hex(weak_key), Colors.RED)
    
    # Run again with same seed
    random.seed(12345)
    weak_key_again = random.getrandbits(128)
    show_result("Repeat Run", hex(weak_key_again), Colors.RED)
    
    if weak_key == weak_key_again:
        show_danger("Same seed → SAME KEY every time! Predictable!")
    
    print()
    print(f"  {Colors.GREEN}GOOD:{Colors.RESET} Using secrets module (crypto-secure RNG)")
    print()
    
    # Good: crypto secure
    strong_key1 = secrets.randbits(128)
    strong_key2 = secrets.randbits(128)
    show_result("Strong Key 1", hex(strong_key1), Colors.GREEN)
    show_result("Strong Key 2", hex(strong_key2), Colors.GREEN)
    
    if strong_key1 != strong_key2:
        show_safe("Each run produces unique, unpredictable keys")
    
    print()
    cprint("  CONCEPT:", Colors.YELLOW, bold=True)
    print("  Never use random.seed() for cryptographic keys.")
    print("  Attackers who know the seed can regenerate your keys.")
    print()
    show_safe("Always use secrets module for crypto operations")
    
    pause(1.2)


# ============================================================================
# DEMO 3: ECB PATTERN LEAKAGE (Pure Python Simulation)
# ============================================================================

def demo_ecb_pattern():
    """Simulate AES-ECB pattern leakage without external libraries"""
    section_header(3, "AES-ECB PATTERN LEAKAGE",
                   "Same input blocks → Same output blocks")
    
    cprint("  What is ECB mode?", Colors.WHITE, bold=True)
    print("  Electronic Codebook (ECB) encrypts each block independently.")
    print("  Identical plaintext blocks produce identical ciphertext.")
    print()
    
    # Simulate visual pattern
    print(f"  {Colors.BOLD}Original Data Pattern:{Colors.RESET}")
    blocks = ["BLACK", "BLACK", "BLACK", "WHITE", "WHITE", "BLACK", "BLACK"]
    for i, block in enumerate(blocks):
        color = Colors.WHITE if block == "WHITE" else Colors.DIM
        print(f"    Block {i+1}: {color}{block}{Colors.RESET}")
    
    print()
    cprint("  ECB Encryption Simulation:", Colors.WHITE, bold=True)
    
    # Simple deterministic "encryption" to simulate ECB
    def fake_ecb_encrypt(block):
        # Deterministic: same input = same output
        return hashlib.md5(block.encode()).hexdigest()[:8].upper()
    
    encrypted_blocks = [fake_ecb_encrypt(b) for b in blocks]
    
    for i, enc in enumerate(encrypted_blocks):
        original = blocks[i]
        color = Colors.YELLOW if original == "WHITE" else Colors.CYAN
        print(f"    Block {i+1}: {color}{enc}{Colors.RESET}  ← from '{original}'")
    
    print()
    print("  Notice how BLACK blocks always become the same ciphertext,")
    print("  and WHITE blocks always become the same ciphertext!")
    print()
    cprint("  CONCEPT:", Colors.YELLOW, bold=True)
    print("  Pattern leakage! If your encrypted image is in ECB mode,")
    print("  you can still see the outline (like the famous ECB penguin).")
    print()
    show_safe("Use AES-GCM or AES-CBC with random IV instead")
    
    pause(1.2)


# ============================================================================
# DEMO 4: PIN BRUTE FORCE SIMULATION
# ============================================================================

def demo_pin_bruteforce():
    """Simulate brute forcing a weak PIN"""
    section_header(4, "WEAK PIN BRUTE FORCE",
                   "Small keyspace = easy to crack")
    
    # Test different PIN lengths
    test_cases = [
        (2, "12"),      # 2-digit
        (3, "456"),     # 3-digit
        (4, "7890"),    # 4-digit
    ]
    
    print(f"  {Colors.BOLD}Simulating brute force on different PIN lengths:{Colors.RESET}")
    print()
    
    for length, correct_pin in test_cases:
        max_value = 10 ** length
        start = time.time()
        
        attempts = 0
        for guess in range(max_value):
            attempts += 1
            if f"{guess:0{length}d}" == correct_pin:
                break
        
        elapsed = (time.time() - start) * 1000  # ms
        
        total_space = 10 ** length
        print(f"  PIN Length {length} ({correct_pin}):")
        show_result("  Keyspace", f"{total_space:,} possibilities", Colors.WHITE)
        show_result("  Attempts needed", f"{attempts:,}", Colors.YELLOW)
        show_result("  Time (Python sim)", f"{elapsed:.2f} ms", Colors.DIM)
        print()
    
    cprint("  CONCEPT:", Colors.YELLOW, bold=True)
    print("  Without rate limiting, short PINs are trivially brute-forced.")
    print("  Even 6-digit OTPs can be cracked if there's no lockout.")
    print()
    show_safe("Implement: rate limiting, account lockout, exponential backoff")
    
    pause(1.2)


# ============================================================================
# DEMO 5: PADDING ORACLE CONCEPT
# ============================================================================

def demo_padding_oracle():
    """Explain padding oracle attack with visual simulation"""
    section_header(5, "PADDING ORACLE ATTACK",
                   "Information leaks via error messages")
    
    cprint("  Attack Flow:", Colors.WHITE, bold=True)
    print()
    
    steps = [
        ("1", "Intercept an encrypted block C[n]"),
        ("2", "Modify the previous block C[n-1]"),
        ("3", "Send modified ciphertext to server"),
        ("4", "Observe response (error message or timing)"),
        ("5", "If padding VALID → guess was correct"),
        ("6", "If padding INVALID → try next guess"),
        ("7", "Repeat byte-by-byte to decrypt full block"),
    ]
    
    for num, step in steps:
        print(f"    {Colors.CYAN}[{num}]{Colors.RESET} {step}")
        pause(0.15)
    
    print()
    print(f"  {Colors.BOLD}Simulating oracle responses:{Colors.RESET}")
    print()
    
    # Simulate oracle responses
    simulated_guesses = [
        (0x00, "INVALID"),
        (0x01, "INVALID"),
        (0x02, "INVALID"),
        (0x03, "VALID  "),
    ]
    
    for byte_val, status in simulated_guesses:
        if status.strip() == "VALID":
            show_safe(f"  Guess 0x{byte_val:02x} → {status} ← Found one byte!")
        else:
            print(f"  Guess 0x{byte_val:02x} → {Colors.RED}{status}{Colors.RESET}")
        pause(0.2)
    
    print()
    cprint("  CONCEPT:", Colors.YELLOW, bold=True)
    print("  If a server reveals whether decryption padding is valid,")
    print("  attackers can decrypt the entire message byte-by-byte.")
    print()
    show_safe("Use authenticated encryption (AES-GCM) or constant-time validation")
    
    pause(1.2)


# ============================================================================
# DEMO 6: TIMING ATTACK SIMULATION
# ============================================================================

def demo_timing_attack():
    """Demonstrate timing attack concept"""
    section_header(6, "TIMING ATTACK",
                   "Microsecond differences leak secrets")
    
    def vulnerable_compare(a, b):
        """Vulnerable: stops at first mismatch"""
        if len(a) != len(b):
            return False
        for i in range(len(a)):
            if a[i] != b[i]:
                return False
        return True
    
    def secure_compare(a, b):
        """Secure: constant-time comparison"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
    secret = b"SECRET_KEY_12345"
    
    test_inputs = [
        (b"XECRET_KEY_12345", "First char wrong"),
        (b"SECRET_KEY_123XX", "Last chars wrong"),
        (b"SECRET_KEY_12345", "Exact match"),
    ]
    
    print(f"  {Colors.BOLD}Testing vulnerable comparison:{Colors.RESET}")
    print()
    
    for test, desc in test_inputs:
        # Run multiple times for stable measurement
        iterations = 10000
        start = time.perf_counter()
        for _ in range(iterations):
            vulnerable_compare(secret, test)
        elapsed = (time.perf_counter() - start) * 1_000_000 / iterations
        
        print(f"  {desc}:")
        print(f"    Input:  {Colors.DIM}{test.decode()}{Colors.RESET}")
        print(f"    Time:   {Colors.YELLOW}{elapsed:.3f} μs{Colors.RESET}")
        print()
    
    print(f"  {Colors.BOLD}Note:{Colors.RESET} Early mismatches return faster!")
    print("  Attackers measure these differences to guess secrets.")
    print()
    cprint("  CONCEPT:", Colors.YELLOW, bold=True)
    print("  Vulnerable code leaks information through timing side-channels.")
    print("  Even nanosecond differences can be measured remotely.")
    print()
    show_safe("Use hmac.compare_digest() for constant-time comparison")
    
    # Show hmac.compare_digest usage
    print()
    print(f"  {Colors.GREEN}Python's built-in solution:{Colors.RESET}")
    print(f"    {Colors.CYAN}import hmac{Colors.RESET}")
    print(f"    {Colors.CYAN}hmac.compare_digest(user_input, secret){Colors.RESET}")
    
    pause(1.2)


# ============================================================================
# DEMO 7: HARDCODED KEY DETECTION
# ============================================================================

def demo_hardcoded_keys():
    """Scan for hardcoded key patterns"""
    section_header(7, "HARDCODED KEY DETECTION",
                   "Finding keys that shouldn't be in code")
    
    # Sample data to scan
    sample_data = b"""
    config = {
        'api_key': 'SECRET_KEY',
        'password': 'admin123',
        'secret': 'AAAAAAAAAAAAAAAA',
        'token': '0000000000000000',
        'db_key': 'password',
    }
    """
    
    print(f"  {Colors.BOLD}Sample data to scan:{Colors.RESET}")
    print(f"  {Colors.DIM}{sample_data.decode()[:200]}{Colors.RESET}")
    print()
    
    # Patterns to look for
    patterns = [
        (b'A' * 16, "Repeated 'A' (16x)"),
        (b'B' * 16, "Repeated 'B' (16x)"),
        (b'0' * 16, "Repeated '0' (16x)"),
        (b'1' * 16, "Repeated '1' (16x)"),
        (b'password', "Literal 'password'"),
        (b'admin', "Literal 'admin'"),
        (b'secret', "Literal 'secret'"),
        (b'key', "Literal 'key'"),
        (b'default', "Literal 'default'"),
        (b'test', "Literal 'test'"),
        (b'1234', "Sequential digits"),
        (b'SECRET_KEY', "Uppercase 'SECRET_KEY'"),
        (b'0000', "Repeated zeros"),
    ]
    
    print(f"  {Colors.BOLD}Scanning for suspicious patterns:{Colors.RESET}")
    print()
    
    found_count = 0
    for pattern, description in patterns:
        if pattern in sample_data:
            found_count += 1
            show_danger(f"FOUND: {description}")
        else:
            print(f"  {Colors.DIM}Clean: {description}{Colors.RESET}")
    
    print()
    show_warning(f"Found {found_count} suspicious pattern(s) in sample data")
    print()
    cprint("  CONCEPT:", Colors.YELLOW, bold=True)
    print("  Hardcoded keys in source code, config files, or binaries")
    print("  are one of the most common crypto vulnerabilities.")
    print("  Attackers can extract them via reverse engineering.")
    print()
    show_safe("Use: environment variables, HSM, Vault, AWS KMS, etc.")
    
    pause(1.2)


# ============================================================================
# DEMO 8: DEPRECATED ALGORITHM DETECTION
# ============================================================================

def demo_deprecated_algorithms():
    """List deprecated cryptographic algorithms"""
    section_header(8, "DEPRECATED ALGORITHMS CHECK",
                   "What NOT to use in 2025")
    
    deprecated = {
        "Hashes": [
            ("MD5", "Collision attacks proven", "SHA-256/3"),
            ("SHA-1", "Collision attacks proven", "SHA-256/3"),
        ],
        "Symmetric Ciphers": [
            ("DES", "56-bit key - brute forcible", "AES-256-GCM"),
            ("3DES", "Sweet32 attack vulnerable", "AES-256-GCM"),
            ("RC4", "Multiple biases discovered", "AES-256-GCM"),
            ("AES-ECB", "Pattern leakage", "AES-256-GCM"),
            ("Blowfish", "64-bit blocks - too small", "AES-256-GCM"),
        ],
        "Asymmetric": [
            ("RSA < 2048", "Factorable with modern compute", "RSA 4096 / ECC"),
            ("DSA < 2048", "Weak signature scheme", "ECDSA P-384"),
        ],
        "Key Exchange": [
            ("DH < 2048", "Logjam attack vulnerable", "ECDHE / X25519"),
            ("Static RSA KX", "No forward secrecy", "ECDHE"),
        ],
    }
    
    for category, algs in deprecated.items():
        cprint(f"  {category}:", Colors.WHITE, bold=True)
        print()
        for name, reason, replacement in algs:
            print(f"    {Colors.RED}[X]{Colors.RESET} {Colors.BOLD}{name}{Colors.RESET}")
            print(f"        Reason:      {Colors.DIM}{reason}{Colors.RESET}")
            print(f"        Replace with: {Colors.GREEN}{replacement}{Colors.RESET}")
            print()
    
    cprint("  CONCEPT:", Colors.YELLOW, bold=True)
    print("  Cryptographic algorithms get broken over time.")
    print("  Regular audits and updates are essential.")
    print()
    show_safe("Always use modern, vetted algorithms from NIST/IETF")
    
    pause(1.2)


# ============================================================================
# SECURITY CHECK TOOLS
# ============================================================================

def tool_password_strength():
    """Check password strength"""
    print()
    cprint("=" * 68, Colors.BLUE)
    cprint("  BONUS TOOL: Password Strength Checker", Colors.BLUE, bold=True)
    cprint("=" * 68, Colors.BLUE)
    print()
    
    test_passwords = [
        "123456",
        "password",
        "Password123!",
        "Tr0ub4dor&3",
        "correct-horse-battery-staple-2025",
    ]
    
    for pwd in test_passwords:
        strength = check_password(pwd)
        color = {
            "CRITICAL": Colors.RED,
            "WEAK": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "STRONG": Colors.GREEN,
        }.get(strength, Colors.WHITE)
        
        print(f"  {Colors.DIM}{pwd:45s}{Colors.RESET} → {color}{strength}{Colors.RESET}")
    
    print()


def check_password(password):
    """Simple password strength checker"""
    if len(password) < 8:
        return "CRITICAL (too short)"
    if password.lower() in ['password', '123456', 'admin', 'qwerty']:
        return "CRITICAL (common)"
    if password.isnumeric():
        return "WEAK (numbers only)"
    if password.isalpha():
        return "WEAK (letters only)"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    length_bonus = len(password) >= 16
    
    score = sum([has_upper, has_lower, has_digit, has_special, length_bonus])
    
    if score >= 4:
        return "STRONG"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "WEAK"


def tool_ssl_recommendations():
    """Show SSL/TLS best practices"""
    print()
    cprint("=" * 68, Colors.BLUE)
    cprint("  BONUS TOOL: TLS/SSL Configuration Guide", Colors.BLUE, bold=True)
    cprint("=" * 68, Colors.BLUE)
    print()
    
    recommendations = [
        ("Protocol Version", "TLS 1.2 or TLS 1.3 ONLY"),
        ("Deprecated", "SSL 2.0, 3.0, TLS 1.0, 1.1 → DISABLE"),
        ("Cipher Suites", "AES-GCM, ChaCha20-Poly1305"),
        ("Key Size", "RSA ≥ 2048 / ECC ≥ 256"),
        ("Forward Secrecy", "Enable ECDHE key exchange"),
        ("HSTS", "Strict-Transport-Security enabled"),
        ("Certificates", "Rotate before expiry, use CRL/OCSP"),
        ("Renegotiation", "Disable client-initiated"),
        ("Compression", "Disable (CRIME attack)"),
    ]
    
    for item, rec in recommendations:
        print(f"  {Colors.CYAN}▸{Colors.RESET} {Colors.BOLD}{item}{Colors.RESET}")
        print(f"    {rec}")
        print()
    
    print()


# ============================================================================
# MAIN PROGRAM
# ============================================================================

def print_banner():
    """Print program banner"""
    clear_screen()
    print()
    cprint("╔" + "═" * 66 + "╗", Colors.CYAN, bold=True)
    cprint("║" + " " * 66 + "║", Colors.CYAN, bold=True)
    cprint("║" + "  CRYPTOGRAPHIC ATTACK DEMONSTRATIONS".center(66) + "║", Colors.CYAN, bold=True)
    cprint("║" + "  Educational Series - 8 Key Concepts".center(66) + "║", Colors.CYAN, bold=True)
    cprint("║" + " " * 66 + "║", Colors.CYAN, bold=True)
    cprint("╚" + "═" * 66 + "╝", Colors.CYAN, bold=True)
    print()
    cprint("  ⚠  WARNING: FOR AUTHORIZED TESTING AND EDUCATION ONLY", Colors.RED, bold=True)
    cprint("  ⚠  Never attack systems you don't own or have permission to test", Colors.RED)
    print()
    cprint("  Python: " + sys.version.split()[0] + "  |  Platform: " + sys.platform, Colors.DIM)
    cprint("  Started: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"), Colors.DIM)
    print()


def print_legal_notice():
    """Print legal notice"""
    print()
    cprint("=" * 68, Colors.RED, bold=True)
    cprint("  IMPORTANT LEGAL AND ETHICAL NOTES", Colors.RED, bold=True)
    cprint("=" * 68, Colors.RED, bold=True)
    print()
    cprint("  1. Only test systems you OWN or have WRITTEN PERMISSION to test", Colors.WHITE)
    cprint("  2. Many attacks require specific environmental conditions", Colors.WHITE)
    cprint("  3. Real implementations are far more complex than these demos", Colors.WHITE)
    cprint("  4. Use this knowledge ONLY for DEFENSIVE security and education", Colors.WHITE)
    cprint("  5. Violating computer fraud laws carries severe penalties", Colors.WHITE)
    print()
    cprint("  Unauthorized access is a FELONY in most jurisdictions:", Colors.YELLOW)
    cprint("  • US: Computer Fraud and Abuse Act (CFAA)", Colors.DIM)
    cprint("  • UK: Computer Misuse Act", Colors.DIM)
    cprint("  • EU: Directive on Attacks Against Information Systems", Colors.DIM)
    print()
    cprint("=" * 68, Colors.RED, bold=True)
    print()


def main():
    """Main entry point"""
    print_banner()
    
    # Wait for user to continue
    cprint("  Press ENTER to start demonstrations (or Ctrl+C to exit)...", Colors.YELLOW, bold=True)
    try:
        input()
    except KeyboardInterrupt:
        print()
        cprint("  Exited by user.", Colors.YELLOW)
        return
    except EOFError:
        # Non-interactive mode - proceed automatically
        pass
    
    # Run all demos
    demos = [
        demo_md5_collision,
        demo_weak_keys,
        demo_ecb_pattern,
        demo_pin_bruteforce,
        demo_padding_oracle,
        demo_timing_attack,
        demo_hardcoded_keys,
        demo_deprecated_algorithms,
    ]
    
    try:
        for i, demo in enumerate(demos, 1):
            demo()
            # Progress indicator
            progress = int((i / len(demos)) * 40)
            bar = "█" * progress + "░" * (40 - progress)
            print()
            cprint(f"  Progress: [{bar}] {i}/{len(demos)}", Colors.CYAN, bold=True)
        
        # Bonus tools
        print()
        cprint("  " + "─" * 64, Colors.DIM)
        cprint("  Running bonus defensive tools...", Colors.WHITE, bold=True)
        tool_password_strength()
        tool_ssl_recommendations()
        
        # Legal notice
        print_legal_notice()
        
        # End
        cprint("=" * 68, Colors.GREEN, bold=True)
        cprint("  ✓ EDUCATION COMPLETE - Use this knowledge responsibly!", Colors.GREEN, bold=True)
        cprint("=" * 68, Colors.GREEN, bold=True)
        print()
        cprint("  Suggested next steps for legal learning:", Colors.YELLOW, bold=True)
        print(f"  {Colors.CYAN}•{Colors.RESET} Try CTF platforms: HTB, TryHackMe, PicoCTF")
        print(f"  {Colors.CYAN}•{Colors.RESET} Practice on Cryptopals Crypto Challenges")
        print(f"  {Colors.CYAN}•{Colors.RESET} Study OWASP Cryptographic Storage Cheat Sheet")
        print(f"  {Colors.CYAN}•{Colors.RESET} Enroll in authorized bug bounty programs")
        print()
        cprint(f"  Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Colors.DIM)
        print()
        
    except KeyboardInterrupt:
        print()
        print()
        cprint("  [!] Interrupted by user", Colors.YELLOW, bold=True)
        print()
    except Exception as e:
        print()
        cprint(f"  [X] Error: {e}", Colors.RED, bold=True)
        print()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        sys.exit(1)
