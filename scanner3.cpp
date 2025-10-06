/*
 scanner2_full_pipeline.cpp (modified)

 Melhorias no Stage 1 (scan / agrupamento por tamanho):

 - Agora faz UMA SÓ travessia do filesystem e agrupa caminhos por tamanho durante a travessia.
 - Para evitar estouro de memória em diretórios enormes, implementa "spill-to-disk":
     * mantém caminhos em memória por tamanho até um limite configurável (max_paths_in_mem)
     * quando o limite é ultrapassado, passa a escrever os caminhos em ficheiros temporários (um ficheiro por tamanho)
 - No fim do Stage 1 constrói a lista de caminhos candidatos (apenas tamanhos com mais de 1 ficheiro)
 - O Stage 2 (partial hashing) passa a consumir essa lista gerada, evitando a re-travessia do disco
 - Progress bar durante a travessia
 - Cria e remove diretório temporário automaticamente
 - Parâmetro opcional [max_paths_in_mem] (por defeito 200000) para ajustar memória permitida antes do spill

 Mantive o resto do pipeline (partial / full) praticamente igual, apenas alterei a forma como os paths candidatos
 são produzidos (já não é feita uma 2ª travessia).
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

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;

// ---------------- SHA-256 (C, optimized) ----------------
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

std::string file_sha256_optimized(const std::string& filepath, size_t buffer_size = 256 * 1024) {
    FILE* f = fopen(filepath.c_str(), "rb");
    if (!f) return "";
    sha256_context ctx;
    sha256_init(&ctx);
    std::unique_ptr<uint8_t[]> buf(new uint8_t[buffer_size]);
    size_t r;
    while ((r = fread(buf.get(), 1, buffer_size, f)) > 0) {
        sha256_update(&ctx, buf.get(), r);
    }
    fclose(f);
    return sha256_hex_from_ctx(ctx);
}

std::string file_partial_hash(const std::string& filepath, size_t partial_bytes = 64 * 1024, size_t buffer_size = 256 * 1024) {
    FILE* f = fopen(filepath.c_str(), "rb");
    if (!f) return "";
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return ""; }
    long long filesize = ftell(f);
    if (filesize < 0) { fclose(f); return ""; }
    sha256_context ctx;
    sha256_init(&ctx);
    std::unique_ptr<uint8_t[]> buf(new uint8_t[buffer_size]);

    size_t to_read = static_cast<size_t>(std::min<long long>(filesize, static_cast<long long>(partial_bytes)));
    if (fseek(f, 0, SEEK_SET) == 0) {
        size_t read_total = 0;
        while (read_total < to_read) {
            size_t want = std::min<size_t>(buffer_size, to_read - read_total);
            size_t r = fread(buf.get(), 1, want, f);
            if (r == 0) break;
            sha256_update(&ctx, buf.get(), r);
            read_total += r;
        }
    }
    if (filesize > static_cast<long long>(2 * partial_bytes)) {
        if (fseek(f, -static_cast<long>(partial_bytes), SEEK_END) == 0) {
            size_t read_total = 0;
            while (read_total < partial_bytes) {
                size_t want = std::min<size_t>(buffer_size, partial_bytes - read_total);
                size_t r = fread(buf.get(), 1, want, f);
                if (r == 0) break;
                sha256_update(&ctx, buf.get(), r);
                read_total += r;
            }
        }
    } else if (filesize > static_cast<long long>(to_read)) {
        if (fseek(f, to_read, SEEK_SET) == 0) {
            long long remain = filesize - to_read;
            size_t read_total = 0;
            while (read_total < static_cast<size_t>(remain)) {
                size_t want = std::min<size_t>(buffer_size, static_cast<size_t>(remain) - read_total);
                size_t r = fread(buf.get(), 1, want, f);
                if (r == 0) break;
                sha256_update(&ctx, buf.get(), r);
                read_total += r;
            }
        }
    }
    fclose(f);
    return sha256_hex_from_ctx(ctx);
}

// ---------------- Thread-safe queue ----------------
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

// ---------------- Progress reporter ----------------
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

// ---------------- Utility ----------------
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

// ---------------- Stage 1 improved: single-pass with spill-to-disk ----------------
//
// Parameters:
//  - max_paths_in_mem: número máximo total de paths mantidos em memória antes de começar a "spillar" para disco.
//  - temp_dir: diretório temporário criado para armazenar ficheiros por tamanho quando necessário.
//
// Strategy:
//  - Durante a travessia, para cada ficheiro válido obtemos o tamanho.
//  - Mantemos:
//      size_count[size] = total de paths vistos desse size
//      size_paths_mem[size] = vector<string> apenas se ainda não spillage para esse size
//      size_tempfile[size] = path para ficheiro temporário (quando um size começou a ser spilled)
//  - Se total_paths_in_memory > max_paths_in_mem, passamos a spill-to-disk para os sizes futuros (e convertendo alguns sizes existentes).
//  - No fim produzimos candidates_paths (apenas para sizes com count > 1), lendo do disco quando necessário.
//
// Returns:
//  - candidates_paths: vector<string> com todos os ficheiros que devem ser avaliados no Stage2 (partial-hash).
//
static void stage1_collect_candidates(const fs::path& root,
                                      uint64_t min_size,
                                      size_t max_paths_in_mem,
                                      std::vector<std::string>& out_candidates,
                                      std::string& out_tempdir,
                                      size_t& out_total_seen) {
    using clock = std::chrono::steady_clock;
    auto t0 = clock::now();

    // containers
    std::unordered_map<uint64_t, size_t> size_count;
    std::unordered_map<uint64_t, std::vector<std::string>> size_paths_mem;
    std::unordered_map<uint64_t, fs::path> size_tempfile; // when spilled: size -> tempfile path
    size_t total_paths_in_mem = 0;
    size_t total_seen = 0;

    // create temp dir for spills
    fs::path tempdir = fs::temp_directory_path() / ("scanner2_tmp_" + std::to_string(::getpid()));
    out_tempdir = tempdir.string();
    try {
        fs::create_directories(tempdir);
    } catch (...) {
        // if cannot create temp dir, we still continue but without spill-to-disk
        tempdir.clear();
    }

    auto append_to_tempfile = [&](uint64_t sz, const std::string& path) {
        try {
            auto it = size_tempfile.find(sz);
            fs::path fp;
            if (it == size_tempfile.end()) {
                // create tempfile named by size (ensure uniquness by pid)
                if (tempdir.empty()) return false;
                fp = tempdir / (std::to_string(sz) + ".txt");
                size_tempfile.emplace(sz, fp);
            } else {
                fp = it->second;
            }
            std::ofstream ofs(fp.string(), std::ios::out | std::ios::app);
            if (!ofs) return false;
            ofs << path << '\n';
            return true;
        } catch (...) {
            return false;
        }
    };

    // traverse filesystem once
    std::cout << "Stage1: traversing filesystem (single-pass)...\n";
    for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
        try {
            if (!fs::is_regular_file(entry.path())) continue;
            uint64_t sz = fs::file_size(entry.path());
            if (sz < min_size) continue;

            ++size_count[sz];
            ++total_seen;

            // decide whether to keep in memory or spill
            if (size_tempfile.find(sz) != size_tempfile.end()) {
                // already spilled for this size: append to its tempfile
                append_to_tempfile(sz, entry.path().string());
            } else {
                // keep in-memory vector
                auto& vec = size_paths_mem[sz];
                vec.push_back(entry.path().string());
                ++total_paths_in_mem;

                // If memory threshold exceeded, convert this size's vector to tempfile (spill)
                if (total_paths_in_mem > max_paths_in_mem && !tempdir.empty()) {
                    // pick sizes to spill: we prefer sizes with largest number of paths to reduce memory quickly
                    // build small list of sizes sorted by current vector size descending
                    std::vector<std::pair<uint64_t, size_t>> sized;
                    sized.reserve(size_paths_mem.size());
                    for (auto& kv : size_paths_mem) sized.emplace_back(kv.first, kv.second.size());
                    std::sort(sized.begin(), sized.end(), [](auto &a, auto &b){ return a.second > b.second; });

                    size_t freed = 0;
                    for (auto& p : sized) {
                        if (total_paths_in_mem <= max_paths_in_mem) break;
                        uint64_t s = p.first;
                        auto itvec = size_paths_mem.find(s);
                        if (itvec == size_paths_mem.end()) continue;
                        // move entries to tempfile
                        for (auto& pathstr : itvec->second) {
                            append_to_tempfile(s, pathstr);
                            --total_paths_in_mem;
                            freed++;
                        }
                        size_paths_mem.erase(itvec);
                    }
                    // if still exceeded but no tempdir or nothing spilled, we keep going (best-effort)
                }
            }

            // tiny progress update
            if ((total_seen & 0xFFFF) == 0) {
                std::cout << "\rFiles scanned: " << total_seen << std::flush;
            }
        } catch (const std::exception&) {
            continue;
        }
    }

    std::cout << "\rFiles scanned: " << total_seen << std::endl;

    // Build out_candidates: only sizes with count > 1
    std::cout << "Stage1: collecting candidate paths for sizes with duplicates...\n";
    for (const auto& kv : size_count) {
        uint64_t sz = kv.first;
        size_t cnt = kv.second;
        if (cnt <= 1) continue;

        // if we have an in-memory vector for this size, append all
        auto it_mem = size_paths_mem.find(sz);
        if (it_mem != size_paths_mem.end()) {
            for (const auto& p : it_mem->second) out_candidates.push_back(p);
            // free mem early
            size_paths_mem.erase(it_mem);
        }

        // if we have a tempfile for this size, read it and append
        auto it_tmp = size_tempfile.find(sz);
        if (it_tmp != size_tempfile.end()) {
            try {
                std::ifstream ifs(it_tmp->second.string());
                std::string line;
                while (std::getline(ifs, line)) {
                    if (!line.empty()) out_candidates.push_back(line);
                }
                // remove tempfile now to save disk
                try { fs::remove(it_tmp->second); } catch(...) {}
            } catch (...) {
                // ignore read errors, continue
            }
        }
    }

    // cleanup tempdir if empty
    if (!tempdir.empty()) {
        try {
            // try remove directory (will fail if not empty)
            fs::remove(tempdir);
        } catch (...) { /* ignore */ }
    }

    auto t1 = clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "Stage1 completed in " << format_duration_ms(dur) << " (" << dur << " ms). Candidates: " << out_candidates.size() << "\n";

    out_total_seen = total_seen;
    out_tempdir = ""; // already cleaned up (path returned only for debugging if needed)
    return;
}

// ---------------- Main pipeline ----------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Uso: " << argv[0] << " <diretorio> [threads] [partial_kb] [buffer_kb] [min_size_bytes] [duplicates_out] [max_paths_in_mem]\n";
        std::cout << "Ex: scanner2_full_pipeline.exe C:\\pasta 8 64 256 1024 duplicates.txt 200000\n";
        return 1;
    }

    fs::path root(argv[1]);
    if (!fs::exists(root) || !fs::is_directory(root)) {
        std::cerr << "Diretorio invalido ou inexistente!\n";
        return 2;
    }

    unsigned int hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = 2;
    unsigned int num_threads = hw;
    if (argc > 2) {
        try { num_threads = std::max<unsigned int>(1, std::stoi(argv[2])); } catch(...) { num_threads = hw; }
    }

    size_t partial_kb = 64;
    if (argc > 3) { try { partial_kb = std::max<size_t>(1, static_cast<size_t>(std::stoul(argv[3]))); } catch(...) { partial_kb = 64; } }
    size_t partial_bytes = partial_kb * 1024;

    size_t buffer_kb = 256;
    if (argc > 4) { try { buffer_kb = std::max<size_t>(4, static_cast<size_t>(std::stoul(argv[4]))); } catch(...) { buffer_kb = 256; } }
    size_t buffer_bytes = buffer_kb * 1024;

    uint64_t min_size = 1;
    if (argc > 5) { try { min_size = std::stoull(argv[5]); } catch(...) { min_size = 1; } }

    std::string duplicates_out = "duplicates.txt";
    if (argc > 6) duplicates_out = argv[6];

    size_t max_paths_in_mem = 200000;
    if (argc > 7) {
        try { max_paths_in_mem = std::stoull(argv[7]); } catch(...) { max_paths_in_mem = 200000; }
    }

    std::cout << "Diretorio: " << root << std::endl;
    std::cout << "Threads: " << num_threads << " (hardware: " << hw << ")\n";
    std::cout << "Partial bytes: " << partial_bytes << " | Buffer: " << buffer_bytes << " bytes | Min size: " << min_size << " bytes\n";
    std::cout << "Duplicates out: " << duplicates_out << "\n";
    std::cout << "Max paths in memory before spilling: " << max_paths_in_mem << "\n\n";

#ifdef _WIN32
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
#endif

    using clock = std::chrono::steady_clock;

    auto t_all_start = clock::now();

    // ---------------- Stage 1 improved ----------------
    std::vector<std::string> candidates;
    std::string tempdir_used;
    size_t total_seen = 0;
    stage1_collect_candidates(root, min_size, max_paths_in_mem, candidates, tempdir_used, total_seen);

    if (candidates.empty()) {
        std::cout << "Nenhum candidato encontrado (nenhum tamanho repetido).\n";
        auto t_all_end = clock::now();
        auto dur_all = std::chrono::duration_cast<std::chrono::milliseconds>(t_all_end - t_all_start).count();
        std::cout << "Total time: " << format_duration_ms(dur_all) << "\n";
        return 0;
    }

    // ---------------- Stage 2: Partial hashing ----------------
    std::cout << "Stage 2: partial hashing (first+last " << partial_bytes << " bytes) on candidate files...\n";
    auto t2_start = clock::now();

    // Queue of candidate file paths -- we now push from collected candidates instead of re-traversal
    ConcurrentQueue<std::string> partial_queue;
    std::atomic<size_t> partial_enqueued{0};

    std::thread producer_partial([&]() {
#ifdef _WIN32
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
#endif
        for (const auto& p : candidates) {
            partial_queue.push(p);
            ++partial_enqueued;
        }
        partial_queue.close();
    });

    // Worker threads for partial hashing; each thread keeps local map partial_hash->vector<path>
    std::vector<std::thread> partial_workers;
    std::vector<std::unordered_map<std::string, std::vector<std::string>>> local_partial_maps;
    local_partial_maps.resize(num_threads);
    for (unsigned int i = 0; i < num_threads; ++i) {
        partial_workers.emplace_back([&, i]() {
#ifdef _WIN32
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#endif
            std::string path;
            size_t local_count = 0;
            auto& local_map = local_partial_maps[i];
            while (partial_queue.pop(path)) {
                std::string ph = file_partial_hash(path, partial_bytes, buffer_bytes);
                if (!ph.empty()) {
                    local_map[ph].push_back(std::move(path));
                }
                ++local_count;
                if ((local_count & 0x1FF) == 0) { // yield occasionally
                    std::this_thread::yield();
                }
            }
        });
    }

    // progress monitoring for partial stage
    std::thread partial_progress([&]() {
        using clock = std::chrono::steady_clock;
        auto start = clock::now();
        while (!partial_queue.empty()) {
            size_t enq = partial_enqueued.load();
            size_t done = 0;
            for (auto& m : local_partial_maps) {
                for (auto& kv : m) done += kv.second.size();
            }
            double percent = enq ? (100.0 * done / enq) : 0.0;
            auto now = clock::now();
            double secs = std::chrono::duration<double>(now - start).count();
            double speed = secs > 0 ? (done / secs) : 0.0;
            double eta = (speed > 0 && enq > done) ? ((enq - done) / speed) : 0.0;
            print_progress_line(percent, done, enq, speed, eta);
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }
    });

    producer_partial.join();
    for (auto& th : partial_workers) if (th.joinable()) th.join();
    if (partial_progress.joinable()) partial_progress.join();

    // Merge local partial maps into global, but only keep groups with >1 file
    std::unordered_map<std::string, std::vector<std::string>> partial_groups;
    partial_groups.reserve(1024);
    for (auto& m : local_partial_maps) {
        for (auto& kv : m) {
            auto& vec = partial_groups[kv.first];
            vec.insert(vec.end(), std::make_move_iterator(kv.second.begin()), std::make_move_iterator(kv.second.end()));
        }
    }

    // Filter partial_groups to only those with >1
    std::vector<std::vector<std::string>> groups_for_full;
    groups_for_full.reserve(1024);
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
    std::cout << "\nStage 2 done in " << format_duration_ms(dur2) << " (" << dur2 << " ms). Groups needing full hash: " << groups_for_full.size() << ", files: " << partial_filtered_files << "\n\n";

    if (groups_for_full.empty()) {
        std::cout << "Nenhum grupo com partial-hash igual. Nenhum duplicado detectado.\n";
        auto t_all_end = clock::now();
        auto dur_all = std::chrono::duration_cast<std::chrono::milliseconds>(t_all_end - t_all_start).count();
        std::cout << "Total time: " << format_duration_ms(dur_all) << "\n";
        return 0;
    }

    // ---------------- Stage 3 and remainder unchanged (use groups_for_full) ----------------
    std::cout << "Stage 3: full SHA-256 hashing for candidate groups...\n";
    auto t3_start = clock::now();

    ConcurrentQueue<std::string> full_queue;
    std::atomic<size_t> full_enqueued{0};
    std::thread producer_full([&]() {
#ifdef _WIN32
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
#endif
        for (auto& group : groups_for_full) {
            for (auto& p : group) {
                full_queue.push(p);
                ++full_enqueued;
            }
        }
        full_queue.close();
    });

    std::vector<std::thread> full_workers;
    std::vector<std::unordered_map<std::string, std::vector<std::string>>> local_full_maps;
    local_full_maps.resize(num_threads);
    for (unsigned int i = 0; i < num_threads; ++i) {
        full_workers.emplace_back([&, i]() {
#ifdef _WIN32
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#endif
            std::string path;
            size_t local_count = 0;
            auto& local_map = local_full_maps[i];
            while (full_queue.pop(path)) {
                std::string fh = file_sha256_optimized(path, buffer_bytes);
                if (!fh.empty()) {
                    local_map[fh].push_back(std::move(path));
                }
                ++local_count;
                if ((local_count & 0xFF) == 0) std::this_thread::yield();
            }
        });
    }

    std::thread full_progress([&]() {
        using clock = std::chrono::steady_clock;
        auto start = clock::now();
        while (!full_queue.empty()) {
            size_t enq = full_enqueued.load();
            size_t done = 0;
            for (auto& m : local_full_maps) {
                for (auto& kv : m) done += kv.second.size();
            }
            double percent = enq ? (100.0 * done / enq) : 0.0;
            auto now = clock::now();
            double secs = std::chrono::duration<double>(now - start).count();
            double speed = secs > 0 ? (done / secs) : 0.0;
            double eta = (speed > 0 && enq > done) ? ((enq - done) / speed) : 0.0;
            print_progress_line(percent, done, enq, speed, eta);
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }
    });

    producer_full.join();
    for (auto& th : full_workers) if (th.joinable()) th.join();
    if (full_progress.joinable()) full_progress.join();

    std::unordered_map<std::string, std::vector<std::string>> final_map;
    final_map.reserve(1024);
    for (auto& m : local_full_maps) {
        for (auto& kv : m) {
            auto& vec = final_map[kv.first];
            vec.insert(vec.end(), std::make_move_iterator(kv.second.begin()), std::make_move_iterator(kv.second.end()));
        }
    }

    auto t3_end = clock::now();
    auto dur3 = std::chrono::duration_cast<std::chrono::milliseconds>(t3_end - t3_start).count();

    std::ofstream out(duplicates_out, std::ios::out | std::ios::trunc);
    if (!out) {
        std::cerr << "Erro ao abrir arquivo de duplicados para escrita: " << duplicates_out << "\n";
    }

    size_t dup_groups = 0;
    size_t duplicates_total = 0;
    for (auto& kv : final_map) {
        if (kv.second.size() > 1) {
            ++dup_groups;
            duplicates_total += kv.second.size();
            if (out) {
                out << "Group " << dup_groups << " (hash=" << kv.first << "):\n";
                for (auto& p : kv.second) out << "  " << p << "\n";
                out << "\n";
            }
        }
    }
    if (out) out.close();

    auto t_all_end = clock::now();
    auto dur_all = std::chrono::duration_cast<std::chrono::milliseconds>(t_all_end - t_all_start).count();

    std::cout << "\nStage 3 done in " << format_duration_ms(dur3) << " (" << dur3 << " ms).\n";
    std::cout << "\n=== SUMMARY ===\n";
    std::cout << "Total time: " << format_duration_ms(dur_all) << " (" << dur_all << " ms)\n";
    std::cout << "Files scanned (stage1): " << total_seen << "\n";
    std::cout << "Files considered for partial hash: " << partial_enqueued.load() << "\n";
    std::cout << "Files considered for full hash: " << full_enqueued.load() << "\n";
    std::cout << "Duplicate groups: " << dup_groups << "\n";
    std::cout << "Duplicate files total: " << duplicates_total << "\n";
    if (dup_groups > 0) std::cout << "Duplicados exportados em: " << duplicates_out << "\n";
    else std::cout << "Nenhum duplicado encontrado.\n";

    return 0;
}