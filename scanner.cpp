/*
 Modificado: agrupamento final foi tornado sensível ao tamanho do ficheiro (size:hash)
 para evitar grupos com arquivos de tamanhos diferentes devido a leituras/colisões/erros.
 Também: não mais executa scan automático na inicialização;

 Atualização: agora consulta a configuração (número de threads) definida pela GUI antes de iniciar cada scan.
*/

#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <chrono>
#include <iomanip>
#include <sstream>

#include <windows.h>
#include <process.h>
#include "gui.h"


namespace fs = std::filesystem;

#ifndef _WIN32
// Page size helper for mmap alignment on POSIX
static inline size_t get_page_size() {
    long p = sysconf(_SC_PAGESIZE);
    if (p <= 0) p = 4096;
    return static_cast<size_t>(p);
}
#endif

// ---------------- SHA-256 Implementation ----------------
typedef struct {
    uint32_t state[8];
    uint8_t buffer[64];
    uint64_t bit_len;
    uint32_t buffer_len;
} sha256_context;

static const uint32_t k_table[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr_u32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t choose_u32(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
static inline uint32_t majority_u32(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
static inline uint32_t sig0_u32(uint32_t x) { return rotr_u32(x, 2) ^ rotr_u32(x, 13) ^ rotr_u32(x, 22); }
static inline uint32_t sig1_u32(uint32_t x) { return rotr_u32(x, 6) ^ rotr_u32(x, 11) ^ rotr_u32(x, 25); }
static inline uint32_t theta0_u32(uint32_t x) { return rotr_u32(x, 7) ^ rotr_u32(x, 18) ^ (x >> 3); }
static inline uint32_t theta1_u32(uint32_t x) { return rotr_u32(x, 17) ^ rotr_u32(x, 19) ^ (x >> 10); }

static void sha256_transform(sha256_context* ctx) {
    uint32_t w[64];
    const uint8_t* buf = ctx->buffer;
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t(buf[i*4]) << 24) | (uint32_t(buf[i*4 + 1]) << 16) |
               (uint32_t(buf[i*4 + 2]) << 8) | uint32_t(buf[i*4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = theta1_u32(w[i - 2]) + w[i - 7] + theta0_u32(w[i - 15]) + w[i - 16];
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i += 8) {
        uint32_t t1, t2;
        t1 = h + sig1_u32(e) + choose_u32(e, f, g) + k_table[i] + w[i];
        t2 = sig0_u32(a) + majority_u32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        t1 = h + sig1_u32(e) + choose_u32(e, f, g) + k_table[i+1] + w[i+1];
        t2 = sig0_u32(a) + majority_u32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        t1 = h + sig1_u32(e) + choose_u32(e, f, g) + k_table[i+2] + w[i+2];
        t2 = sig0_u32(a) + majority_u32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        t1 = h + sig1_u32(e) + choose_u32(e, f, g) + k_table[i+3] + w[i+3];
        t2 = sig0_u32(a) + majority_u32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        t1 = h + sig1_u32(e) + choose_u32(e, f, g) + k_table[i+4] + w[i+4];
        t2 = sig0_u32(a) + majority_u32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        t1 = h + sig1_u32(e) + choose_u32(e, f, g) + k_table[i+5] + w[i+5];
        t2 = sig0_u32(a) + majority_u32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        t1 = h + sig1_u32(e) + choose_u32(e, f, g) + k_table[i+6] + w[i+6];
        t2 = sig0_u32(a) + majority_u32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;

        t1 = h + sig1_u32(e) + choose_u32(e, f, g) + k_table[i+7] + w[i+7];
        t2 = sig0_u32(a) + majority_u32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_context* ctx) {
    ctx->bit_len = 0;
    ctx->buffer_len = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_context* ctx, const uint8_t* data, size_t len) {
    size_t i = 0;
    while (i < len) {
        size_t to_copy = std::min<size_t>(len - i, 64 - ctx->buffer_len);
        memcpy(ctx->buffer + ctx->buffer_len, data + i, to_copy);
        ctx->buffer_len += static_cast<uint32_t>(to_copy);
        i += to_copy;
        if (ctx->buffer_len == 64) {
            sha256_transform(ctx);
            ctx->bit_len += 512;
            ctx->buffer_len = 0;
        }
    }
}

static void sha256_final(sha256_context* ctx, uint8_t* hash_out) {
    uint32_t i = ctx->buffer_len;
    uint64_t total_bits = ctx->bit_len + ctx->buffer_len * 8ULL;

    if (ctx->buffer_len < 56) {
        ctx->buffer[i++] = 0x80;
        while (i < 56) ctx->buffer[i++] = 0x00;
    } else {
        ctx->buffer[i++] = 0x80;
        while (i < 64) ctx->buffer[i++] = 0x00;
        sha256_transform(ctx);
        memset(ctx->buffer, 0, 56);
    }

    for (int j = 7; j >= 0; --j)
        ctx->buffer[56 + j] = static_cast<uint8_t>((total_bits >> (j * 8)) & 0xFF);

    sha256_transform(ctx);

    for (i = 0; i < 4; ++i) {
        hash_out[i]      = (ctx->state[0] >> ((3 - i) * 8)) & 0xFF;
        hash_out[i + 4]  = (ctx->state[1] >> ((3 - i) * 8)) & 0xFF;
        hash_out[i + 8]  = (ctx->state[2] >> ((3 - i) * 8)) & 0xFF;
        hash_out[i + 12] = (ctx->state[3] >> ((3 - i) * 8)) & 0xFF;
        hash_out[i + 16] = (ctx->state[4] >> ((3 - i) * 8)) & 0xFF;
        hash_out[i + 20] = (ctx->state[5] >> ((3 - i) * 8)) & 0xFF;
        hash_out[i + 24] = (ctx->state[6] >> ((3 - i) * 8)) & 0xFF;
        hash_out[i + 28] = (ctx->state[7] >> ((3 - i) * 8)) & 0xFF;
    }
}

static std::string sha256_hex_from_ctx(sha256_context& ctx) {
    uint8_t hash[32];
    sha256_final(&ctx, hash);
    char hex[65];
    static const char* hexchars = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hex[i * 2] = hexchars[(hash[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hexchars[hash[i] & 0xF];
    }
    hex[64] = '\0';
    return std::string(hex);
}

// ---------------- File Hashing Functions (optimized) ----------------

// On POSIX use mmap chunked reads (fast). On Windows use large buffered reads with FILE_FLAG_SEQUENTIAL_SCAN.
std::string file_sha256_optimized(const std::string& filepath, size_t buffer_size = 4 * 1024 * 1024) {
#ifdef _WIN32
    HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";
    LARGE_INTEGER fileSizeLI;
    if (!GetFileSizeEx(hFile, &fileSizeLI)) { CloseHandle(hFile); return ""; }
    uint64_t filesize = (uint64_t)fileSizeLI.QuadPart;
    if (filesize == 0) { CloseHandle(hFile); return ""; }

    sha256_context ctx;
    sha256_init(&ctx);
    std::unique_ptr<uint8_t[]> buf(new uint8_t[buffer_size]);

    DWORD toRead = 0;
    DWORD read = 0;
    OVERLAPPED ov = {};
    // Synchronous ReadFile loop (overlapped zero) — large buffers reduce syscall overhead
    uint64_t remaining = filesize;
    while (remaining > 0) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(buffer_size, remaining));
        BOOL ok = ReadFile(hFile, buf.get(), (DWORD)want, &read, NULL);
        if (!ok) break;
        if (read == 0) break;
        sha256_update(&ctx, buf.get(), (size_t)read);
        remaining -= read;
    }

    CloseHandle(hFile);
    return sha256_hex_from_ctx(ctx);
#else
    int fd = open(filepath.c_str(), O_RDONLY);
    if (fd < 0) return "";
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return ""; }
    off_t filesize = st.st_size;
    if (filesize == 0) { close(fd); return ""; }

    // Advise kernel for sequential reading (may improve readahead)
#ifdef POSIX_FADV_SEQUENTIAL
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

    sha256_context ctx;
    sha256_init(&ctx);

    const size_t chunk = buffer_size;
    const size_t page = get_page_size();
    off_t offset = 0;
    while (offset < filesize) {
        size_t mapSize = static_cast<size_t>(std::min<off_t>((off_t)chunk, filesize - offset));
        off_t aligned_off = (off_t)((uint64_t)offset & ~((uint64_t)page - 1ULL));
        size_t delta = static_cast<size_t>(offset - aligned_off);
        size_t map_len = delta + mapSize;
        void* map = mmap(nullptr, map_len, PROT_READ, MAP_SHARED, fd, aligned_off);
        if (map != MAP_FAILED) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(map) + delta;
            sha256_update(&ctx, p, mapSize);
            munmap(map, map_len);
        } else {
            // fallback to read()
            if (lseek(fd, offset, SEEK_SET) == -1) break;
            std::unique_ptr<uint8_t[]> buf(new uint8_t[buffer_size]);
            size_t remain = mapSize;
            while (remain > 0) {
                ssize_t r = read(fd, buf.get(), std::min<size_t>(buffer_size, remain));
                if (r <= 0) { remain = 0; break; }
                sha256_update(&ctx, buf.get(), (size_t)r);
                remain -= (size_t)r;
            }
        }
        offset += mapSize;
    }
    close(fd);
    return sha256_hex_from_ctx(ctx);
#endif
}

std::string file_partial_hash(const std::string& filepath, size_t partial_bytes = 64 * 1024, size_t buffer_size = 4 * 1024 * 1024) {
#ifdef _WIN32
    HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";
    LARGE_INTEGER fileSizeLI;
    if (!GetFileSizeEx(hFile, &fileSizeLI)) { CloseHandle(hFile); return ""; }
    uint64_t filesize = (uint64_t)fileSizeLI.QuadPart;
    if (filesize == 0) { CloseHandle(hFile); return ""; }

    sha256_context ctx;
    sha256_init(&ctx);
    std::unique_ptr<uint8_t[]> buf(new uint8_t[buffer_size]);

    // Read first partial_bytes
    uint64_t first_read = std::min<uint64_t>(partial_bytes, filesize);
    {
        DWORD read = 0;
        uint64_t remaining = first_read;
        while (remaining > 0) {
            DWORD want = (DWORD)std::min<uint64_t>(buffer_size, remaining);
            if (!ReadFile(hFile, buf.get(), want, &read, NULL) || read == 0) break;
            sha256_update(&ctx, buf.get(), (size_t)read);
            remaining -= read;
        }
    }

    if (filesize > 2 * partial_bytes) {
        // Read last partial_bytes
        uint64_t off = filesize - partial_bytes;
        // move file pointer
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)off;
        SetFilePointerEx(hFile, li, NULL, FILE_BEGIN);
        DWORD read = 0;
        uint64_t remaining = partial_bytes;
        while (remaining > 0) {
            DWORD want = (DWORD)std::min<uint64_t>(buffer_size, remaining);
            if (!ReadFile(hFile, buf.get(), want, &read, NULL) || read == 0) break;
            sha256_update(&ctx, buf.get(), (size_t)read);
            remaining -= read;
        }
    } else if (filesize > first_read) {
        // Read remaining middle part if file small-ish
        uint64_t off = first_read;
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)off;
        SetFilePointerEx(hFile, li, NULL, FILE_BEGIN);
        uint64_t remaining = filesize - first_read;
        DWORD read = 0;
        while (remaining > 0) {
            DWORD want = (DWORD)std::min<uint64_t>(buffer_size, remaining);
            if (!ReadFile(hFile, buf.get(), want, &read, NULL) || read == 0) break;
            sha256_update(&ctx, buf.get(), (size_t)read);
            remaining -= read;
        }
    }

    CloseHandle(hFile);
    return sha256_hex_from_ctx(ctx);
#else
    int fd = open(filepath.c_str(), O_RDONLY);
    if (fd < 0) return "";
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return ""; }
    off_t filesize = st.st_size;
    if (filesize == 0) { close(fd); return ""; }

#ifdef POSIX_FADV_SEQUENTIAL
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

    sha256_context ctx;
    sha256_init(&ctx);

    size_t first_read = (size_t)std::min<off_t>(partial_bytes, filesize);
    // map first block
    {
        void* m = mmap(nullptr, first_read, PROT_READ, MAP_SHARED, fd, 0);
        if (m != MAP_FAILED) {
            sha256_update(&ctx, reinterpret_cast<const uint8_t*>(m), first_read);
            munmap(m, first_read);
        } else {
            if (lseek(fd, 0, SEEK_SET) != -1) {
                std::unique_ptr<uint8_t[]> buf(new uint8_t[std::min<size_t>(buffer_size, first_read)]);
                size_t toread = first_read;
                while (toread > 0) {
                    ssize_t r = read(fd, buf.get(), std::min<size_t>(buffer_size, toread));
                    if (r <= 0) break;
                    sha256_update(&ctx, buf.get(), (size_t)r);
                    toread -= (size_t)r;
                }
            }
        }
    }

    if (filesize > 2 * (off_t)partial_bytes) {
        off_t off = filesize - partial_bytes;
        const size_t page = get_page_size();
        off_t aligned_off = (off_t)((uint64_t)off & ~((uint64_t)page - 1ULL));
        size_t delta = static_cast<size_t>(off - aligned_off);
        size_t map_len = delta + partial_bytes;
        void* m2 = mmap(nullptr, map_len, PROT_READ, MAP_SHARED, fd, aligned_off);
        if (m2 != MAP_FAILED) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(m2) + delta;
            sha256_update(&ctx, p, partial_bytes);
            munmap(m2, map_len);
        } else {
            if (lseek(fd, off, SEEK_SET) != -1) {
                std::unique_ptr<uint8_t[]> buf(new uint8_t[std::min<size_t>(buffer_size, partial_bytes)]);
                size_t remain = partial_bytes;
                while (remain > 0) {
                    ssize_t r = read(fd, buf.get(), std::min<size_t>(buffer_size, remain));
                    if (r <= 0) break;
                    sha256_update(&ctx, buf.get(), (size_t)r);
                    remain -= (size_t)r;
                }
            }
        }
    } else if (filesize > (off_t)first_read) {
        off_t off = first_read;
        off_t remain = filesize - first_read;
        const size_t page = get_page_size();
        off_t aligned_off = (off_t)((uint64_t)off & ~((uint64_t)page - 1ULL));
        size_t delta = static_cast<size_t>(off - aligned_off);
        size_t map_len = static_cast<size_t>(remain) + delta;
        void* m2 = mmap(nullptr, map_len, PROT_READ, MAP_SHARED, fd, aligned_off);
        if (m2 != MAP_FAILED) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(m2) + delta;
            sha256_update(&ctx, p, (size_t)remain);
            munmap(m2, map_len);
        } else {
            if (lseek(fd, off, SEEK_SET) != -1) {
                std::unique_ptr<uint8_t[]> buf(new uint8_t[buffer_size]);
                size_t read_total = 0;
                while (read_total < (size_t)remain) {
                    ssize_t r = read(fd, buf.get(), std::min<size_t>(buffer_size, (size_t)remain - read_total));
                    if (r <= 0) break;
                    sha256_update(&ctx, buf.get(), (size_t)r);
                    read_total += (size_t)r;
                }
            }
        }
    }

    close(fd);
    return sha256_hex_from_ctx(ctx);
#endif
}

// ---------------- Thread-safe Queue ----------------
template<typename T>
class ConcurrentQueue {
private:
    std::queue<T> q;
    std::mutex m;
    std::condition_variable cv;
    std::atomic<bool> closed{false};
public:
    void push(const T& item) {
        {
            std::lock_guard<std::mutex> lk(m);
            q.push(item);
        }
        cv.notify_one();
    }
    bool pop(T& out) {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [&]() { return !q.empty() || closed.load(); });
        if (q.empty()) return false;
        out = std::move(q.front());
        q.pop();
        return true;
    }
    void close() {
        closed.store(true);
        cv.notify_all();
    }
    bool empty() {
        std::lock_guard<std::mutex> lk(m);
        return q.empty();
    }
};

// ---------------- Progress Reporting ----------------
void print_progress_line(double percent, size_t done, size_t total, double speed, double eta) {
    const size_t bar_width = 40;
    size_t pos = static_cast<size_t>(bar_width * percent / 100.0);
    std::ostringstream oss;
    oss << "\r[";
    for (size_t i = 0; i < bar_width; ++i) {
        if (i < pos) oss << '=';
        else if (i == pos) oss << '>';
        else oss << ' ';
    }
    oss << "] " << std::setw(3) << std::fixed << std::setprecision(0) << percent << "% ";
    oss << done << "/" << total << " ";
    oss << std::fixed << std::setprecision(2) << speed << " files/s ";
    if (eta > 0.5) {
        int e = static_cast<int>(eta);
        int hh = e / 3600; int mm = (e % 3600) / 60; int ss = e % 60;
        oss << "ETA " << std::setw(2) << std::setfill('0') << hh << ":" << std::setw(2) << mm << ":" << std::setw(2) << ss;
    } else {
        oss << "ETA --:--:--";
    }
    std::cout << oss.str() << std::flush;
}

std::string format_duration_ms(long long ms) {
    long long s = ms / 1000;
    int hh = static_cast<int>(s / 3600);
    int mm = static_cast<int>((s % 3600) / 60);
    int ss = static_cast<int>(s % 60);
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << hh << ":"
        << std::setw(2) << std::setfill('0') << mm << ":"
        << std::setw(2) << std::setfill('0') << ss;
    return oss.str();
}

// ---------------- Stage 1: File Size Grouping with Spill-to-Disk ----------------
static void stage1_collect_candidates(const fs::path& root,
                                      uint64_t min_size,
                                      size_t max_paths_in_mem,
                                      std::vector<std::string>& out_candidates,
                                      std::string& out_tempdir,
                                      size_t& out_total_seen) {
    using clock = std::chrono::steady_clock;
    auto t0 = clock::now();

    std::unordered_map<uint64_t, size_t> size_count;
    std::unordered_map<uint64_t, std::vector<std::string>> size_paths_mem;
    // Single spill file to reduce overhead
    fs::path spill_path;
    bool have_spill = false;
    std::unique_ptr<std::ofstream> spill_ofs;
    size_t total_paths_in_mem = 0;
    size_t total_seen = 0;

    std::ostringstream td;
#ifdef _WIN32
    td << "scanner_tmp_" << GetCurrentProcessId() << "_" << std::chrono::high_resolution_clock::now().time_since_epoch().count();
#else
    td << "scanner_tmp_" << getpid() << "_" << std::chrono::high_resolution_clock::now().time_since_epoch().count();
#endif
    fs::path tempdir = fs::temp_directory_path() / td.str();
    out_tempdir = tempdir.string();
    try { fs::create_directories(tempdir); } catch(...) { tempdir.clear(); }

    auto ensure_spill_open = [&]() -> bool {
        if (tempdir.empty()) return false;
        if (!have_spill) {
            spill_path = tempdir / "spill.txt";
            spill_ofs.reset(new std::ofstream(spill_path.string(), std::ios::out | std::ios::app));
            have_spill = spill_ofs && (*spill_ofs);
        }
        return have_spill;
    };

    std::cout << "Stage1: Analisando sistema de arquivos...\n";
    for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
        try {
            if (!fs::is_regular_file(entry.path())) continue;
            uint64_t sz = fs::file_size(entry.path());
            if (sz < min_size) continue;

            ++size_count[sz];
            ++total_seen;

            // Accumulate in memory and spill in batches if memory limit exceeded
            auto& vec = size_paths_mem[sz];
            vec.push_back(entry.path().string());
            ++total_paths_in_mem;

            if (total_paths_in_mem > max_paths_in_mem && ensure_spill_open()) {
                std::vector<std::pair<uint64_t, size_t>> sized;
                sized.reserve(size_paths_mem.size());
                for (auto& kv : size_paths_mem) sized.emplace_back(kv.first, kv.second.size());
                std::sort(sized.begin(), sized.end(), [](auto &a, auto &b){ return a.second > b.second; });

                for (auto& p : sized) {
                    if (total_paths_in_mem <= max_paths_in_mem) break;
                    uint64_t s = p.first;
                    auto itvec = size_paths_mem.find(s);
                    if (itvec == size_paths_mem.end()) continue;
                    for (auto& pathstr : itvec->second) {
                        (*spill_ofs) << s << '\t' << pathstr << '\n';
                        --total_paths_in_mem;
                    }
                    size_paths_mem.erase(itvec);
                }
            }

            if ((total_seen & 0xFFFF) == 0) std::cout << "\rArquivos escaneados: " << total_seen << std::flush;
        } catch (...) { continue; }
    }
    std::cout << "\rArquivos escaneados: " << total_seen << std::endl;

    std::cout << "Stage1: Coletando candidatos...\n";
    // Close spill file before reading
    if (have_spill && spill_ofs) { spill_ofs->flush(); spill_ofs->close(); }

    // Collect in-memory groups for sizes with more than one occurrence
    for (const auto& kv : size_count) {
        uint64_t sz = kv.first;
        size_t cnt = kv.second;
        if (cnt <= 1) continue;
        auto it_mem = size_paths_mem.find(sz);
        if (it_mem != size_paths_mem.end()) {
            for (const auto& p : it_mem->second) out_candidates.push_back(p);
        }
    }

    // Read spilled entries (size\tpath) and include only sizes with count > 1
    if (have_spill) {
        try {
            std::ifstream ifs(spill_path.string());
            std::string line;
            while (std::getline(ifs, line)) {
                if (line.empty()) continue;
                size_t tab = line.find('\t');
                if (tab == std::string::npos) continue;
                uint64_t sz = 0;
                try { sz = std::stoull(line.substr(0, tab)); } catch (...) { continue; }
                auto itc = size_count.find(sz);
                if (itc == size_count.end() || itc->second <= 1) continue;
                std::string path = line.substr(tab + 1);
                if (!path.empty()) out_candidates.push_back(std::move(path));
            }
        } catch (...) {}
    }

    if (!tempdir.empty()) {
        try { fs::remove_all(tempdir); } catch(...) {}
    }

    auto t1 = clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "Stage1 concluido em " << format_duration_ms(dur) << ". Candidatos: " << out_candidates.size() << "\n";

    out_total_seen = total_seen;
    out_tempdir.clear();
}

// ---------------- File Identity (Hard Link) Utilities ----------------
static std::string get_file_unique_id(const std::string& path) {
#ifdef _WIN32
    HANDLE h = CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    BY_HANDLE_FILE_INFORMATION info;
    BOOL ok = GetFileInformationByHandle(h, &info);
    CloseHandle(h);
    if (!ok) return std::string();
    std::ostringstream oss;
    oss << std::hex << info.dwVolumeSerialNumber << ':' << info.nFileIndexHigh << ':' << info.nFileIndexLow;
    return oss.str();
#else
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) return std::string();
    std::ostringstream oss;
    oss << std::hex << (uint64_t)st.st_dev << ':' << (uint64_t)st.st_ino;
    return oss.str();
#endif
}

// ---------------- Utility Functions ----------------
static fs::path get_executable_dir() {
#ifdef _WIN32
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, buf, MAX_PATH);
    if (len == 0 || len == MAX_PATH) return fs::current_path();
    fs::path exe_path(buf);
    return exe_path.parent_path();
#else
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (len != -1) {
        buf[len] = '\0';
        fs::path exe_path(buf);
        return exe_path.parent_path();
    } else {
        return fs::current_path();
    }
#endif
}

// ---------------- Scanner Configuration ----------------
struct ScannerConfig {
    unsigned int num_threads;
    size_t partial_kb;
    size_t buffer_kb;
    uint64_t min_size;
    size_t max_paths_in_mem;
    std::string mode;
    std::string duplicates_out;
    
    ScannerConfig() {
        unsigned int hw = std::thread::hardware_concurrency();
        if (hw == 0) hw = 2;
        // Heurística agressiva por padrão: 2x cores (limitado), pode ser ajustada via argv
        unsigned int guessed = std::min<unsigned int>(std::max<unsigned int>(1, hw * 2), 32);
        num_threads = guessed;
        partial_kb = 64;            // 64 KB partial read blocks (boa filtragem)
        buffer_kb = 4096;          // 4 MiB buffer por thread (melhor throughput)
        min_size = 1;
        max_paths_in_mem = 200000;
        mode = "same";
        duplicates_out = "duplicates.txt";
    }
};

// ---------------- Main Scanner Function ----------------
int scan_directory(const std::string& directory_path, const ScannerConfig& config = ScannerConfig(), bool is_new_scan = false) {
    fs::path root = fs::path(directory_path);

    if (!fs::exists(root) || !fs::is_directory(root)) {
        std::cerr << "Diretorio invalido: " << root << "\n";
        if (is_new_scan) {
#ifdef _WIN32
            MessageBoxA(NULL, "Diretorio invalido ou inacessivel.", "Erro", MB_OK | MB_ICONERROR);
#endif
            return 2;
        }
        return 2;
    }

    size_t partial_bytes = config.partial_kb * 1024;
    size_t buffer_bytes = config.buffer_kb * 1024;

    std::cout << "\n=== VERIFICACAO DE DUPLICADOS ===\n";
    std::cout << "Diretorio: " << root << std::endl;
    std::cout << "Threads: " << config.num_threads << "\n";
    std::cout << "Partial bytes: " << partial_bytes << " | Buffer: " << buffer_bytes << " | Min size: " << config.min_size << "\n\n";

#ifdef _WIN32
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
#endif

    using clock = std::chrono::steady_clock;
    auto t_all_start = clock::now();

    // Stage 1
    std::vector<std::string> candidates;
    std::string tmpdir;
    size_t total_seen = 0;
    stage1_collect_candidates(root, config.min_size, config.max_paths_in_mem, candidates, tmpdir, total_seen);

    if (candidates.empty()) {
        std::cout << "Nenhum candidato encontrado.\n";
        std::vector<std::pair<std::string, std::vector<std::string>>> empty_groups;
        std::vector<std::string> info_msg;
        std::ostringstream msg;
        msg << "Nenhum arquivo duplicado encontrado em: " << root.string();
        msg << "\n\nEstatisticas da verificacao:";
        msg << "\n- Arquivos analisados: " << total_seen;
        msg << "\n- Candidatos a duplicados: 0";
        msg << "\n\nTodos os arquivos no diretorio sao unicos!";
        info_msg.push_back(msg.str());
        empty_groups.emplace_back("INFO|no_duplicates", info_msg);
        show_results_window(empty_groups, "Verificador de Arquivos Duplicados - Nenhum Duplicado Encontrado");
        return 0;
    }

    // Stage 2: Partial hash
    std::cout << "Stage 2: Hash parcial...\n";
    auto t2_start = clock::now();

    ConcurrentQueue<std::string> partial_queue;
    std::atomic<size_t> partial_enqueued{0};
    std::thread producer_partial([&]() {
        for (const auto& p : candidates) { partial_queue.push(p); ++partial_enqueued; }
        partial_queue.close();
    });

    std::vector<std::thread> partial_workers;
    std::vector<std::unordered_map<std::string, std::vector<std::string>>> local_partial_maps;
    local_partial_maps.resize(config.num_threads);
    for (unsigned int i = 0; i < config.num_threads; ++i) {
        partial_workers.emplace_back([&, i]() {
            std::string path;
            auto& local_map = local_partial_maps[i];
            while (partial_queue.pop(path)) {
                std::string ph = file_partial_hash(path, partial_bytes, buffer_bytes);
                if (!ph.empty()) local_map[ph].push_back(std::move(path));
            }
        });
    }

    producer_partial.join();
    for (auto& th : partial_workers) if (th.joinable()) th.join();

    std::unordered_map<std::string, std::vector<std::string>> partial_groups;
    partial_groups.reserve(local_partial_maps.size() * 4);
    for (auto& m : local_partial_maps)
        for (auto& kv : m) partial_groups[kv.first].insert(partial_groups[kv.first].end(),
                                                           std::make_move_iterator(kv.second.begin()),
                                                           std::make_move_iterator(kv.second.end()));

    std::vector<std::vector<std::string>> groups_for_full;
    size_t partial_filtered_files = 0;
    for (auto& kv : partial_groups) {
        if (kv.second.size() > 1) { 
            partial_filtered_files += kv.second.size(); 
            groups_for_full.push_back(std::move(kv.second)); 
        }
    }
    partial_groups.clear();
    auto t2_end = clock::now();
    auto dur2 = std::chrono::duration_cast<std::chrono::milliseconds>(t2_end - t2_start).count();
    std::cout << "Stage 2 concluido em " << format_duration_ms(dur2) << ". Grupos para hash completo: "
              << groups_for_full.size() << ", arquivos: " << partial_filtered_files << "\n\n";

    if (groups_for_full.empty()) {
        std::cout << "Nenhum duplicado detectado.\n";
        std::vector<std::pair<std::string, std::vector<std::string>>> empty_groups;
        std::vector<std::string> info_msg;
        std::ostringstream msg;
        msg << "Nenhum arquivo duplicado encontrado em: " << root.string();
        msg << "\n\nEstatisticas da verificacao:";
        msg << "\n- Arquivos analisados: " << total_seen;
        msg << "\n- Candidatos iniciais: " << candidates.size();
        msg << "\n- Duplicados encontrados: 0";
        msg << "\n\nApesar de alguns arquivos terem o mesmo tamanho,";
        msg << "\nnenhum conteudo duplicado foi detectado.";
        info_msg.push_back(msg.str());
        empty_groups.emplace_back("INFO|no_duplicates", info_msg);
        show_results_window(empty_groups, "Verificador de Arquivos Duplicados - Nenhum Duplicado Encontrado");
        return 0;
    }

    // Stage 3: Full hash
    std::cout << "Stage 3: Hash SHA-256 completo...\n";
    auto t3_start = clock::now();

    ConcurrentQueue<std::string> full_queue;
    std::atomic<size_t> full_enqueued{0};
    std::thread producer_full([&]() {
        for (auto& group : groups_for_full) for (auto& p : group) { full_queue.push(p); ++full_enqueued; }
        full_queue.close();
    });

    std::vector<std::thread> full_workers;
    std::vector<std::unordered_map<std::string, std::vector<std::string>>> local_full_maps;
    local_full_maps.resize(config.num_threads);
    for (unsigned int i = 0; i < config.num_threads; ++i) {
        full_workers.emplace_back([&, i]() {
            std::string path;
            auto& local_map = local_full_maps[i];
            while (full_queue.pop(path)) {
                std::string fh = file_sha256_optimized(path, buffer_bytes);
                if (!fh.empty()) local_map[fh].push_back(std::move(path));
            }
        });
    }

    producer_full.join();
    for (auto& th : full_workers) if (th.joinable()) th.join();

    // Merge local full maps into final_map BUT key by size:hash to avoid mixing different sizes in same group
    std::unordered_map<std::string, std::vector<std::string>> final_map; // key: "<size>:<hash>"
    final_map.reserve(local_full_maps.size() * 8);

    for (auto& m : local_full_maps) {
        for (auto& kv : m) {
            const std::string& hash = kv.first;
            for (auto& path : kv.second) {
                uint64_t sz = 0;
                try {
                    sz = fs::file_size(path);
                } catch (...) {
                    sz = 0;
                    std::cerr << "Aviso: falha ao obter tamanho de arquivo: " << path << "\n";
                }
                std::string key = std::to_string(sz) + ":" + hash;
                final_map[key].push_back(path);
            }
        }
    }

    // Filter out hard links (same physical file) within each size:hash group
    for (auto& kv : final_map) {
        auto& vec = kv.second;
        std::vector<std::string> filtered;
        filtered.reserve(vec.size());
        std::unordered_set<std::string> seen_ids;
        for (auto& p : vec) {
            std::string id = get_file_unique_id(p);
            if (id.empty()) {
                filtered.push_back(std::move(p));
            } else if (seen_ids.insert(id).second) {
                filtered.push_back(std::move(p));
            }
        }
        vec.swap(filtered);
    }

    auto t3_end = clock::now();
    auto dur3 = std::chrono::duration_cast<std::chrono::milliseconds>(t3_end - t3_start).count();

    // Group by mode
    std::unordered_map<std::string, std::vector<std::string>> output_groups;
    if (config.mode == "all") {
        // In "all" mode we simply expose the final_map (size:hash keys)
        output_groups = std::move(final_map);
    } else {
        // For "same" (parent directory grouping), include size in the key so different sizes with same hash don't mix
        for (const auto& kv : final_map) {
            const std::string& size_hash = kv.first; // "<size>:<hash>"
            for (const auto& path : kv.second) {
                fs::path pp(path);
                std::string parent = pp.parent_path().string();
                std::string key = parent + "|" + size_hash;
                output_groups[key].push_back(path);
            }
        }
    }

    // Export and show results
    std::ofstream out(config.duplicates_out);
    size_t dup_groups = 0;
    size_t duplicates_total = 0;
    std::vector<std::pair<std::string, std::vector<std::string>>> gui_groups;
    for (const auto& kv : output_groups) {
        if (kv.second.size() > 1) {
            ++dup_groups;
            duplicates_total += kv.second.size();
            if (out) {
                out << "Grupo " << dup_groups << ":\n";
                for (const auto& p : kv.second) out << "  " << p << "\n";
                out << "\n";
            }
            gui_groups.emplace_back(kv.first, kv.second);
        }
    }

    auto t_all_end = clock::now();
    auto dur_all = std::chrono::duration_cast<std::chrono::milliseconds>(t_all_end - t_all_start).count();

    std::cout << "Stage 3 concluido em " << format_duration_ms(dur3) << "\n";
    std::cout << "\n=== RESUMO ===\n";
    std::cout << "Tempo total: " << format_duration_ms(dur_all) << "\n";
    std::cout << "Arquivos escaneados: " << total_seen << "\n";
    std::cout << "Grupos de duplicados: " << dup_groups << "\n";
    std::cout << "Total de arquivos duplicados: " << duplicates_total << "\n";

    if (gui_groups.empty()) {
        // Ainda assim, mostrar uma janela informativa
        std::vector<std::string> info_msg;
        std::ostringstream msg;
        msg << "Verificacao concluida em: " << root.string();
        msg << "\n\nEstatisticas finais:";
        msg << "\n- Arquivos analisados: " << total_seen;
        msg << "\n- Candidatos iniciais: " << candidates.size();
        msg << "\n- Arquivos com hash parcial identico: " << partial_filtered_files;
        msg << "\n- Duplicados encontrados: 0";
        msg << "\n\nTodos os arquivos sao unicos!";
        info_msg.push_back(msg.str());
        gui_groups.emplace_back("INFO|no_duplicates", info_msg);
        
        show_results_window(gui_groups, "Verificador de Arquivos Duplicados - Verificacao Concluida");
    } else {
        show_results_window(gui_groups, "Verificador de Arquivos Duplicados");
    }
    
    return 0;
}

// ---------------- New Scan Callback (runs scan in background to avoid UI freeze) ----------------
void handle_new_scan_request(const std::string& directory) {
    // Run scan in a detached worker thread so UI thread is not blocked.
    // Before starting, query the GUI for the user-selected configuration (number of threads etc).
    std::thread([directory]() {
        std::cout << "\n=== NOVA VERIFICACAO: " << directory << " ===\n";
        ScannerConfig config;
        try {
            GUIConfig gcfg = get_gui_scanner_config();
            if (gcfg.num_threads > 0) {
                config.num_threads = gcfg.num_threads;
            }
            // Map other GUI fields if you expand GUIConfig in the future:
            // config.partial_kb = gcfg.partial_kb;
            // config.buffer_kb  = gcfg.buffer_kb;
            // config.min_size   = gcfg.min_size;
        } catch (...) {
            // fallback to defaults already in ScannerConfig()
        }
        scan_directory(directory, config, true); // marca como nova verificação
    }).detach();
}

// ---------------- Main Entry Point ----------------
int main(int argc, char* argv[]) {
    set_new_scan_callback(handle_new_scan_request);

    // Instead of starting a scan on startup, show the GUI and instruct the user to click "Nova Pasta".
    // Prepare a single informational group to display in the first tab explaining the workflow.
    std::vector<std::pair<std::string, std::vector<std::string>>> info_groups;
    std::vector<std::string> msg;
    std::ostringstream oss;
    oss << "Clique em 'Nova Pasta' para iniciar uma verificacao. Use o campo 'Threads' para ajustar quantos threads o scanner deve usar.\n";
    oss << "Voce pode iniciar multiplas verificacoes em paralelo; os resultados aparecerao em abas separadas nesta janela.\n\n";
    msg.push_back(oss.str());
    info_groups.emplace_back("INFO|welcome", msg);

    show_results_window(info_groups, "Verificador de Arquivos Duplicados");

    return 0;
}