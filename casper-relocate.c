#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#define NAR_VERSION_MAGIC "nix-archive-1"
#define NAR_MAX_TAG 32
#define NAR_MAX_NAME 255
#define NAR_MAX_TARGET 4095
#define NAR_MAX_DEPTH 1024
#define CASPER_SCAN_FD 3

typedef struct {
    char *old_str;
    size_t old_len;
    const char *new_str;
    size_t new_len;
} reloc_pair_t;

static reloc_pair_t *g_pairs = NULL;
static size_t g_num_pairs = 0;
static size_t g_pairs_cap = 0;
static size_t g_min_old_len = 0;
static size_t g_max_old_len = 0;
static int g_all_same_len = 1;
static int g_scan_fd = -1;

static void die(const char *msg) {
    size_t len = strlen(msg);
    ssize_t r = write(STDERR_FILENO, msg, len);
    (void)r;
    r = write(STDERR_FILENO, "\n", 1);
    (void)r;
    _exit(1);
}

static void read_exact(uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(STDIN_FILENO, buf + off, n - off);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            die("casper-relocate: read error on stdin");
        }
        if (r == 0)
            die("casper-relocate: unexpected EOF on stdin");
        off += (size_t)r;
    }
}

static void write_exact(int fd, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            die("casper-relocate: write error on stdout");
        }
        off += (size_t)w;
    }
}

static void write_scan(const uint8_t *buf, size_t n) {
    if (g_scan_fd < 0 || n == 0)
        return;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(g_scan_fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EBADF || errno == EPIPE) {
                g_scan_fd = -1;
                return;
            }
            die("casper-relocate: write error on scan fd 3");
        }
        off += (size_t)w;
    }
}

typedef struct {
    int is_mem;
    uint8_t *data;
    size_t len;
    size_t cap;
} sink_t;

static void sink_write(sink_t *s, const void *buf, size_t n) {
    if (n == 0)
        return;
    if (!s->is_mem) {
        write_exact(STDOUT_FILENO, (const uint8_t *)buf, n);
        return;
    }
    if (s->len + n > s->cap) {
        size_t new_cap = s->cap ? s->cap * 2 : 4096;
        while (new_cap < s->len + n)
            new_cap *= 2;
        uint8_t *nb = (uint8_t *)realloc(s->data, new_cap);
        if (!nb)
            die("casper-relocate: out of memory");
        s->data = nb;
        s->cap = new_cap;
    }
    memcpy(s->data + s->len, buf, n);
    s->len += n;
}

static uint64_t read_u64(void) {
    uint8_t b[8];
    read_exact(b, 8);
    return (uint64_t)b[0]
        | ((uint64_t)b[1] << 8)
        | ((uint64_t)b[2] << 16)
        | ((uint64_t)b[3] << 24)
        | ((uint64_t)b[4] << 32)
        | ((uint64_t)b[5] << 40)
        | ((uint64_t)b[6] << 48)
        | ((uint64_t)b[7] << 56);
}

static void write_u64(sink_t *s, uint64_t v) {
    uint8_t b[8];
    b[0] = (uint8_t)(v & 0xff);
    b[1] = (uint8_t)((v >> 8) & 0xff);
    b[2] = (uint8_t)((v >> 16) & 0xff);
    b[3] = (uint8_t)((v >> 24) & 0xff);
    b[4] = (uint8_t)((v >> 32) & 0xff);
    b[5] = (uint8_t)((v >> 40) & 0xff);
    b[6] = (uint8_t)((v >> 48) & 0xff);
    b[7] = (uint8_t)((v >> 56) & 0xff);
    sink_write(s, b, 8);
}

static void read_pad(uint64_t len) {
    size_t pad = (size_t)((8 - (len & 7)) & 7);
    if (pad > 0) {
        uint8_t b[8];
        read_exact(b, pad);
        for (size_t i = 0; i < pad; i++) {
            if (b[i] != 0)
                die("casper-relocate: non-zero NAR padding");
        }
    }
}

static void write_pad(sink_t *s, uint64_t len) {
    static const uint8_t zeros[8] = {0};
    size_t pad = (size_t)((8 - (len & 7)) & 7);
    if (pad > 0)
        sink_write(s, zeros, pad);
}

static char *read_str(size_t max_len, size_t *out_len) {
    uint64_t len = read_u64();
    if (len > max_len)
        die("casper-relocate: NAR string exceeds maximum length");
    char *s = (char *)malloc((size_t)len + 1);
    if (!s)
        die("casper-relocate: out of memory");
    if (len > 0)
        read_exact((uint8_t *)s, (size_t)len);
    s[len] = '\0';
    read_pad(len);
    if (out_len)
        *out_len = (size_t)len;
    return s;
}

static void write_bytes(sink_t *s, const void *buf, size_t len) {
    write_u64(s, (uint64_t)len);
    if (len > 0)
        sink_write(s, buf, len);
    write_pad(s, (uint64_t)len);
}

static void write_cstr(sink_t *s, const char *str) {
    write_bytes(s, str, strlen(str));
}

static void expect_tag(const char *expected) {
    size_t len = 0;
    char *tag = read_str(NAR_MAX_TAG, &len);
    if (strcmp(tag, expected) != 0)
        die("casper-relocate: unexpected NAR tag");
    free(tag);
}

static int find_earliest_match(
    const uint8_t *buf,
    size_t buf_len,
    size_t max_start_excl,
    size_t *out_off,
    size_t *out_pair_idx)
{
    if (g_num_pairs == 0 || max_start_excl == 0 || buf_len < g_min_old_len)
        return 0;

    int found = 0;
    size_t best_off = 0;
    size_t best_idx = 0;
    size_t best_olen = 0;

    for (size_t i = 0; i < g_num_pairs; i++) {
        size_t olen = g_pairs[i].old_len;
        if (olen > buf_len)
            continue;

        size_t max_pos = buf_len - olen;
        if (max_pos > max_start_excl - 1)
            max_pos = max_start_excl - 1;

        if (found) {
            if (olen > best_olen) {
                if (max_pos > best_off)
                    max_pos = best_off;
            } else {
                if (best_off == 0)
                    continue;
                if (max_pos > best_off - 1)
                    max_pos = best_off - 1;
            }
        }

        size_t search_len = max_pos + olen;
        const uint8_t *m = (const uint8_t *)memmem(buf, search_len, g_pairs[i].old_str, olen);
        if (m != NULL) {
            best_off = (size_t)(m - buf);
            best_idx = i;
            best_olen = olen;
            found = 1;
        }
    }

    if (!found)
        return 0;
    *out_off = best_off;
    *out_pair_idx = best_idx;
    return 1;
}

static uint8_t *replace_all(const uint8_t *in, size_t in_len, size_t *out_len, int *out_changed) {
    if (out_changed)
        *out_changed = 0;

    if (g_num_pairs == 0 || in_len < g_min_old_len) {
        uint8_t *copy = (uint8_t *)malloc(in_len + 1);
        if (!copy)
            die("casper-relocate: out of memory");
        if (in_len > 0)
            memcpy(copy, in, in_len);
        copy[in_len] = '\0';
        *out_len = in_len;
        return copy;
    }

    size_t match_count = 0;
    size_t final_len = 0;
    size_t pos = 0;
    while (in_len - pos >= g_min_old_len) {
        size_t rel_off = 0;
        size_t pair_idx = 0;
        if (!find_earliest_match(in + pos, in_len - pos, in_len - pos, &rel_off, &pair_idx))
            break;
        match_count++;
        final_len += rel_off + g_pairs[pair_idx].new_len;
        pos += rel_off + g_pairs[pair_idx].old_len;
    }
    final_len += in_len - pos;

    if (match_count == 0) {
        uint8_t *copy = (uint8_t *)malloc(in_len + 1);
        if (!copy)
            die("casper-relocate: out of memory");
        memcpy(copy, in, in_len);
        copy[in_len] = '\0';
        *out_len = in_len;
        return copy;
    }

    if (out_changed)
        *out_changed = 1;

    uint8_t *out = (uint8_t *)malloc(final_len + 1);
    if (!out)
        die("casper-relocate: out of memory");

    uint8_t *dst = out;
    pos = 0;
    while (in_len - pos >= g_min_old_len) {
        size_t rel_off = 0;
        size_t pair_idx = 0;
        if (!find_earliest_match(in + pos, in_len - pos, in_len - pos, &rel_off, &pair_idx))
            break;
        if (rel_off > 0) {
            memcpy(dst, in + pos, rel_off);
            dst += rel_off;
        }
        size_t nlen = g_pairs[pair_idx].new_len;
        if (nlen > 0) {
            memcpy(dst, g_pairs[pair_idx].new_str, nlen);
            dst += nlen;
        }
        pos += rel_off + g_pairs[pair_idx].old_len;
    }
    if (pos < in_len) {
        size_t rem = in_len - pos;
        memcpy(dst, in + pos, rem);
        dst += rem;
    }
    *dst = '\0';
    *out_len = final_len;
    return out;
}

static int gzip_decompress(const uint8_t *in, size_t in_len, uint8_t **out_buf, size_t *out_len) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (inflateInit2(&strm, 15 + 16) != Z_OK)
        return -1;

    size_t cap = in_len * 2;
    if (cap < 4096)
        cap = 4096;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) {
        inflateEnd(&strm);
        die("casper-relocate: out of memory");
    }

    strm.next_in = (Bytef *)in;
    strm.avail_in = 0;
    size_t in_off = 0;
    size_t total_out = 0;

    while (1) {
        if (strm.avail_in == 0 && in_off < in_len) {
            size_t chunk = in_len - in_off;
            if (chunk > 0x40000000U)
                chunk = 0x40000000U;
            strm.next_in = (Bytef *)(in + in_off);
            strm.avail_in = (uInt)chunk;
            in_off += chunk;
        }
        if (total_out == cap) {
            cap *= 2;
            uint8_t *nb = (uint8_t *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                inflateEnd(&strm);
                die("casper-relocate: out of memory");
            }
            buf = nb;
        }
        size_t avail_space = cap - total_out;
        if (avail_space > 0x40000000U)
            avail_space = 0x40000000U;
        strm.next_out = buf + total_out;
        strm.avail_out = (uInt)avail_space;

        int ret = inflate(&strm, Z_NO_FLUSH);
        total_out += avail_space - strm.avail_out;

        if (ret == Z_STREAM_END) {
            if (strm.avail_in > 0 || in_off < in_len) {
                if (inflateReset(&strm) != Z_OK) {
                    free(buf);
                    inflateEnd(&strm);
                    return -1;
                }
                continue;
            }
            break;
        }
        if (ret != Z_OK) {
            free(buf);
            inflateEnd(&strm);
            return -1;
        }
    }

    inflateEnd(&strm);
    *out_buf = buf;
    *out_len = total_out;
    return 0;
}

static int gzip_compress_deterministic(const uint8_t *in, size_t in_len, uint8_t **out_buf, size_t *out_len) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return -1;

    gz_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.time = 0;
    hdr.os = 3; /* Unix */
    if (deflateSetHeader(&strm, &hdr) != Z_OK) {
        deflateEnd(&strm);
        return -1;
    }

    size_t cap = deflateBound(&strm, (uLong)in_len) + 64;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) {
        deflateEnd(&strm);
        die("casper-relocate: out of memory");
    }

    size_t in_off = 0;
    size_t total_out = 0;

    while (1) {
        if (strm.avail_in == 0 && in_off < in_len) {
            size_t chunk = in_len - in_off;
            if (chunk > 0x40000000U)
                chunk = 0x40000000U;
            strm.next_in = (Bytef *)(in + in_off);
            strm.avail_in = (uInt)chunk;
            in_off += chunk;
        }
        if (total_out == cap) {
            cap *= 2;
            uint8_t *nb = (uint8_t *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                deflateEnd(&strm);
                die("casper-relocate: out of memory");
            }
            buf = nb;
        }
        size_t avail_space = cap - total_out;
        if (avail_space > 0x40000000U)
            avail_space = 0x40000000U;
        strm.next_out = buf + total_out;
        strm.avail_out = (uInt)avail_space;

        int flush = (in_off == in_len && strm.avail_in == 0) ? Z_FINISH : Z_NO_FLUSH;
        int ret = deflate(&strm, flush);
        total_out += avail_space - strm.avail_out;

        if (ret == Z_STREAM_END)
            break;
        if (ret != Z_OK) {
            free(buf);
            deflateEnd(&strm);
            return -1;
        }
    }

    deflateEnd(&strm);
    *out_buf = buf;
    *out_len = total_out;
    return 0;
}

static int has_gz_suffix(const char *name) {
    if (!name)
        return 0;
    size_t len = strlen(name);
    return len >= 3 && strcmp(name + len - 3, ".gz") == 0;
}

static void stream_regular_same_len(sink_t *out, uint64_t size) {
    write_u64(out, size);
    if (size == 0)
        return;

    const size_t chunk_cap = 65536;
    if (g_num_pairs == 0) {
        uint8_t buf[65536];
        uint64_t remaining = size;
        while (remaining > 0) {
            size_t to_read = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;
            read_exact(buf, to_read);
            sink_write(out, buf, to_read);
            remaining -= to_read;
        }
        read_pad(size);
        write_pad(out, size);
        return;
    }

    size_t buf_cap = chunk_cap + g_max_old_len;
    uint8_t *buf = (uint8_t *)malloc(buf_cap);
    if (!buf)
        die("casper-relocate: out of memory");

    size_t carry = 0;
    uint64_t remaining = size;

    while (remaining > 0) {
        size_t to_read = remaining > chunk_cap ? chunk_cap : (size_t)remaining;
        read_exact(buf + carry, to_read);
        remaining -= to_read;
        size_t total = carry + to_read;

        size_t pos = 0;
        if (remaining > 0) {
            while (total - pos >= g_max_old_len) {
                size_t rem_in_buf = total - pos;
                size_t max_start_excl = rem_in_buf - g_max_old_len + 1;
                size_t rel_off = 0;
                size_t pair_idx = 0;
                if (!find_earliest_match(buf + pos, rem_in_buf, max_start_excl, &rel_off, &pair_idx))
                    break;
                memcpy(buf + pos + rel_off, g_pairs[pair_idx].new_str, g_pairs[pair_idx].new_len);
                pos += rel_off + g_pairs[pair_idx].old_len;
            }

            size_t safe = total > (g_max_old_len - 1) ? total - (g_max_old_len - 1) : 0;
            if (safe < pos)
                safe = pos;
            if (safe > 0)
                sink_write(out, buf, safe);
            carry = total - safe;
            if (carry > 0)
                memmove(buf, buf + safe, carry);
        } else {
            while (total - pos >= g_min_old_len) {
                size_t rem_in_buf = total - pos;
                size_t rel_off = 0;
                size_t pair_idx = 0;
                if (!find_earliest_match(buf + pos, rem_in_buf, rem_in_buf, &rel_off, &pair_idx))
                    break;
                memcpy(buf + pos + rel_off, g_pairs[pair_idx].new_str, g_pairs[pair_idx].new_len);
                pos += rel_off + g_pairs[pair_idx].old_len;
            }
            sink_write(out, buf, total);
            carry = 0;
        }
    }

    free(buf);
    read_pad(size);
    write_pad(out, size);
}

typedef struct {
    char *name;
    uint8_t *node_data;
    size_t node_len;
} deferred_entry_t;

static int cmp_deferred(const void *a, const void *b) {
    const deferred_entry_t *da = (const deferred_entry_t *)a;
    const deferred_entry_t *db = (const deferred_entry_t *)b;
    return strcmp(da->name, db->name);
}

static void process_node(sink_t *out, const char *entry_name, int depth) {
    if (depth >= NAR_MAX_DEPTH)
        die("casper-relocate: maximum NAR depth exceeded");

    expect_tag("(");
    expect_tag("type");
    char *type = read_str(NAR_MAX_TAG, NULL);

    if (strcmp(type, "regular") == 0) {
        char *tag = read_str(NAR_MAX_TAG, NULL);
        int executable = 0;
        if (strcmp(tag, "executable") == 0) {
            free(tag);
            size_t empty_len = 0;
            char *empty = read_str(0, &empty_len);
            free(empty);
            executable = 1;
            tag = read_str(NAR_MAX_TAG, NULL);
        }
        if (strcmp(tag, "contents") != 0)
            die("casper-relocate: expected 'contents' tag");
        free(tag);

        uint64_t size = read_u64();

        write_cstr(out, "(");
        write_cstr(out, "type");
        write_cstr(out, "regular");
        if (executable) {
            write_cstr(out, "executable");
            write_cstr(out, "");
        }
        write_cstr(out, "contents");

        if (has_gz_suffix(entry_name) && size > 0) {
            uint8_t *compressed = (uint8_t *)malloc((size_t)size);
            if (!compressed)
                die("casper-relocate: out of memory");
            read_exact(compressed, (size_t)size);
            read_pad(size);

            uint8_t *decompressed = NULL;
            size_t decomp_len = 0;
            int rewritten_gz = 0;
            uint8_t *final_gz = NULL;
            size_t final_gz_len = 0;

            if (gzip_decompress(compressed, (size_t)size, &decompressed, &decomp_len) == 0) {
                size_t first_off = 0;
                size_t first_idx = 0;
                if (find_earliest_match(decompressed, decomp_len, decomp_len, &first_off, &first_idx)) {
                    size_t rew_len = 0;
                    int changed = 0;
                    uint8_t *rew = replace_all(decompressed, decomp_len, &rew_len, &changed);
                    write_scan(rew, rew_len);
                    write_scan((const uint8_t *)"\n", 1);
                    if (gzip_compress_deterministic(rew, rew_len, &final_gz, &final_gz_len) == 0)
                        rewritten_gz = 1;
                    free(rew);
                } else {
                    write_scan(decompressed, decomp_len);
                    write_scan((const uint8_t *)"\n", 1);
                }
                free(decompressed);
            }

            if (rewritten_gz) {
                write_bytes(out, final_gz, final_gz_len);
                free(final_gz);
            } else {
                write_bytes(out, compressed, (size_t)size);
            }
            free(compressed);
        } else if (g_all_same_len) {
            stream_regular_same_len(out, size);
        } else {
            uint8_t *raw = (uint8_t *)malloc((size_t)size ? (size_t)size : 1);
            if (!raw)
                die("casper-relocate: out of memory");
            if (size > 0)
                read_exact(raw, (size_t)size);
            read_pad(size);
            size_t rew_len = 0;
            uint8_t *rew = replace_all(raw, (size_t)size, &rew_len, NULL);
            free(raw);
            write_bytes(out, rew, rew_len);
            free(rew);
        }

        expect_tag(")");
        write_cstr(out, ")");
    } else if (strcmp(type, "symlink") == 0) {
        expect_tag("target");
        size_t target_len = 0;
        char *target = read_str(NAR_MAX_TARGET, &target_len);
        expect_tag(")");

        size_t new_target_len = 0;
        uint8_t *new_target = replace_all((const uint8_t *)target, target_len, &new_target_len, NULL);
        free(target);

        write_cstr(out, "(");
        write_cstr(out, "type");
        write_cstr(out, "symlink");
        write_cstr(out, "target");
        write_bytes(out, new_target, new_target_len);
        write_cstr(out, ")");
        free(new_target);
    } else if (strcmp(type, "directory") == 0) {
        write_cstr(out, "(");
        write_cstr(out, "type");
        write_cstr(out, "directory");

        deferred_entry_t *deferred = NULL;
        size_t deferred_cnt = 0;
        size_t deferred_cap = 0;

        while (1) {
            char *tag = read_str(NAR_MAX_TAG, NULL);
            if (strcmp(tag, ")") == 0) {
                free(tag);
                if (deferred_cnt > 1)
                    qsort(deferred, deferred_cnt, sizeof(deferred_entry_t), cmp_deferred);
                for (size_t i = 0; i < deferred_cnt; i++) {
                    write_cstr(out, "entry");
                    write_cstr(out, "(");
                    write_cstr(out, "name");
                    write_cstr(out, deferred[i].name);
                    write_cstr(out, "node");
                    sink_write(out, deferred[i].node_data, deferred[i].node_len);
                    write_cstr(out, ")");
                    free(deferred[i].name);
                    free(deferred[i].node_data);
                }
                free(deferred);
                write_cstr(out, ")");
                break;
            }
            if (strcmp(tag, "entry") != 0)
                die("casper-relocate: expected 'entry' or ')' tag in directory");
            free(tag);

            expect_tag("(");
            expect_tag("name");
            size_t name_len = 0;
            char *name = read_str(NAR_MAX_NAME, &name_len);
            expect_tag("node");

            size_t new_name_len = 0;
            char *new_name = (char *)replace_all((const uint8_t *)name, name_len, &new_name_len, NULL);

            if (strcmp(new_name, name) != 0) {
                sink_t mem_sink = {1, NULL, 0, 0};
                process_node(&mem_sink, new_name, depth + 1);
                expect_tag(")");

                if (deferred_cnt == deferred_cap) {
                    deferred_cap = deferred_cap ? deferred_cap * 2 : 8;
                    deferred = (deferred_entry_t *)realloc(deferred, deferred_cap * sizeof(deferred_entry_t));
                    if (!deferred)
                        die("casper-relocate: out of memory");
                }
                deferred[deferred_cnt].name = new_name;
                deferred[deferred_cnt].node_data = mem_sink.data;
                deferred[deferred_cnt].node_len = mem_sink.len;
                deferred_cnt++;
                free(name);
            } else {
                free(new_name);
                if (deferred_cnt > 1)
                    qsort(deferred, deferred_cnt, sizeof(deferred_entry_t), cmp_deferred);
                size_t keep = 0;
                for (size_t i = 0; i < deferred_cnt; i++) {
                    if (strcmp(deferred[i].name, name) < 0) {
                        write_cstr(out, "entry");
                        write_cstr(out, "(");
                        write_cstr(out, "name");
                        write_cstr(out, deferred[i].name);
                        write_cstr(out, "node");
                        sink_write(out, deferred[i].node_data, deferred[i].node_len);
                        write_cstr(out, ")");
                        free(deferred[i].name);
                        free(deferred[i].node_data);
                    } else {
                        deferred[keep++] = deferred[i];
                    }
                }
                deferred_cnt = keep;

                write_cstr(out, "entry");
                write_cstr(out, "(");
                write_cstr(out, "name");
                write_cstr(out, name);
                write_cstr(out, "node");
                process_node(out, name, depth + 1);
                expect_tag(")");
                write_cstr(out, ")");
                free(name);
            }
        }
    } else {
        die("casper-relocate: unknown NAR node type");
    }

    free(type);
}

static void record_pair(const char *old_s, size_t old_len, const char *new_s, size_t new_len) {
    for (size_t i = 0; i < g_num_pairs; i++) {
        if (g_pairs[i].old_len == old_len && memcmp(g_pairs[i].old_str, old_s, old_len) == 0) {
            g_pairs[i].new_str = new_s;
            g_pairs[i].new_len = new_len;
            return;
        }
    }
    if (g_num_pairs == g_pairs_cap) {
        g_pairs_cap = g_pairs_cap ? g_pairs_cap * 2 : 8;
        g_pairs = (reloc_pair_t *)realloc(g_pairs, g_pairs_cap * sizeof(reloc_pair_t));
        if (!g_pairs)
            die("casper-relocate: out of memory");
    }
    char *old_copy = (char *)malloc(old_len + 1);
    if (!old_copy)
        die("casper-relocate: out of memory");
    memcpy(old_copy, old_s, old_len);
    old_copy[old_len] = '\0';
    g_pairs[g_num_pairs].old_str = old_copy;
    g_pairs[g_num_pairs].old_len = old_len;
    g_pairs[g_num_pairs].new_str = new_s;
    g_pairs[g_num_pairs].new_len = new_len;
    g_num_pairs++;
}

static void finalize_pairs(void) {
    size_t keep = 0;
    for (size_t i = 0; i < g_num_pairs; i++) {
        if (g_pairs[i].old_len == g_pairs[i].new_len
            && memcmp(g_pairs[i].old_str, g_pairs[i].new_str, g_pairs[i].old_len) == 0) {
            free(g_pairs[i].old_str);
            continue;
        }
        g_pairs[keep++] = g_pairs[i];
    }
    g_num_pairs = keep;

    g_all_same_len = 1;
    if (g_num_pairs == 0) {
        g_min_old_len = 0;
        g_max_old_len = 0;
        return;
    }

    g_min_old_len = g_pairs[0].old_len;
    g_max_old_len = g_pairs[0].old_len;
    for (size_t i = 0; i < g_num_pairs; i++) {
        if (g_pairs[i].old_len < g_min_old_len)
            g_min_old_len = g_pairs[i].old_len;
        if (g_pairs[i].old_len > g_max_old_len)
            g_max_old_len = g_pairs[i].old_len;
        if (g_pairs[i].old_len != g_pairs[i].new_len)
            g_all_same_len = 0;
    }
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    int fl = fcntl(CASPER_SCAN_FD, F_GETFL);
    if (fl != -1) {
        int acc = fl & O_ACCMODE;
        if (acc == O_WRONLY || acc == O_RDWR)
            g_scan_fd = CASPER_SCAN_FD;
    }

    if (argc >= 2 && strchr(argv[1], ':') != NULL) {
        for (int i = 1; i < argc; i++) {
            const char *colon = strchr(argv[i], ':');
            if (!colon)
                die("casper-relocate: expected <old>:<new> argument");
            if (strchr(colon + 1, ':') != NULL)
                die("casper-relocate: ambiguous ':' in <old>:<new> argument");
            size_t old_len = (size_t)(colon - argv[i]);
            const char *new_s = colon + 1;
            size_t new_len = strlen(new_s);
            if (old_len == 0 && new_len == 0)
                continue;
            if (old_len == 0)
                die("casper-relocate: empty <old> in <old>:<new> argument");
            record_pair(argv[i], old_len, new_s, new_len);
        }
    } else if (argc == 3) {
        if (strchr(argv[2], ':') != NULL)
            die("casper-relocate: unexpected ':' in legacy 2-argument mode");
        if (argv[1][0] != '\0' && argv[2][0] != '\0')
            record_pair(argv[1], strlen(argv[1]), argv[2], strlen(argv[2]));
    } else if (argc == 1 || (argc == 2 && argv[1][0] == '\0')) {
        /* Scan-only or raw passthrough */
    } else {
        die("usage: casper-relocate (<old> <new> | <old1>:<new1> [<old2>:<new2> ...])");
    }

    finalize_pairs();

    if (g_num_pairs == 0 && g_scan_fd < 0) {
        uint8_t buf[65536];
        while (1) {
            ssize_t r = read(STDIN_FILENO, buf, sizeof(buf));
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                die("casper-relocate: read error");
            }
            if (r == 0)
                break;
            write_exact(STDOUT_FILENO, buf, (size_t)r);
        }
        return 0;
    }

    sink_t stdout_sink = {0, NULL, 0, 0};
    expect_tag(NAR_VERSION_MAGIC);
    write_cstr(&stdout_sink, NAR_VERSION_MAGIC);
    process_node(&stdout_sink, "", 0);
    return 0;
}
