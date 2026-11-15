#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NAR_VERSION_MAGIC "nix-archive-1"
#define NAR_MAX_TAG 32
#define NAR_MAX_NAME 255
#define NAR_MAX_TARGET 4095
#define NAR_MAX_DEPTH 1024

static void die(const char *msg) {
    size_t len = strlen(msg);
    ssize_t r = write(STDERR_FILENO, msg, len);
    (void)r;
    r = write(STDERR_FILENO, "\n", 1);
    (void)r;
    _exit(1);
}

static void read_exact(int fd, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            die("casper-nar: read error");
        }
        if (r == 0)
            die("casper-nar: unexpected EOF");
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
            die("casper-nar: write error");
        }
        off += (size_t)w;
    }
}

static uint64_t read_u64(void) {
    uint8_t b[8];
    read_exact(STDIN_FILENO, b, 8);
    return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 24)
         | ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

static void write_u64(uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)((v >> (i * 8)) & 0xffu);
    write_exact(STDOUT_FILENO, b, 8);
}

static void read_pad(uint64_t len) {
    size_t rem = (size_t)(len & 7u);
    if (rem != 0) {
        uint8_t pad[8];
        size_t n = 8 - rem;
        read_exact(STDIN_FILENO, pad, n);
        for (size_t i = 0; i < n; i++) {
            if (pad[i] != 0)
                die("casper-nar: non-zero NAR padding");
        }
    }
}

static void write_pad(uint64_t len) {
    size_t rem = (size_t)(len & 7u);
    if (rem != 0) {
        static const uint8_t zeros[8] = {0};
        write_exact(STDOUT_FILENO, zeros, 8 - rem);
    }
}

static char *read_str(size_t max_len) {
    uint64_t len = read_u64();
    if (len > max_len)
        die("casper-nar: string exceeds max length");
    char *s = (char *)malloc((size_t)len + 1);
    if (!s)
        die("casper-nar: out of memory");
    if (len > 0)
        read_exact(STDIN_FILENO, (uint8_t *)s, (size_t)len);
    s[len] = '\0';
    if (memchr(s, '\0', (size_t)len) != NULL)
        die("casper-nar: embedded NUL in NAR string");
    read_pad(len);
    return s;
}

static void expect_tag(const char *expected) {
    char *s = read_str(NAR_MAX_TAG);
    if (strcmp(s, expected) != 0)
        die("casper-nar: unexpected NAR tag");
    free(s);
}

static void write_bytes(const uint8_t *buf, size_t len) {
    write_u64((uint64_t)len);
    if (len > 0)
        write_exact(STDOUT_FILENO, buf, len);
    write_pad((uint64_t)len);
}

static void write_cstr(const char *s) {
    write_bytes((const uint8_t *)s, strlen(s));
}

static char *join_path(const char *dir, const char *name) {
    size_t dlen = strlen(dir);
    size_t nlen = strlen(name);
    char *res = (char *)malloc(dlen + 1 + nlen + 1);
    if (!res)
        die("casper-nar: out of memory");
    memcpy(res, dir, dlen);
    res[dlen] = '/';
    memcpy(res + dlen + 1, name, nlen + 1);
    return res;
}

static void restore_node(const char *path, int depth) {
    if (depth >= NAR_MAX_DEPTH)
        die("casper-nar: max NAR depth exceeded");

    expect_tag("(");
    expect_tag("type");
    char *type = read_str(NAR_MAX_TAG);

    if (strcmp(type, "regular") == 0) {
        free(type);
        char *tag = read_str(NAR_MAX_TAG);
        int executable = 0;
        if (strcmp(tag, "executable") == 0) {
            free(tag);
            char *empty = read_str(0);
            free(empty);
            executable = 1;
            tag = read_str(NAR_MAX_TAG);
        }
        if (strcmp(tag, "contents") != 0)
            die("casper-nar: expected contents tag");
        free(tag);

        uint64_t size = read_u64();
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, executable ? 0755 : 0644);
        if (fd < 0)
            die("casper-nar: failed to create regular file");

        uint8_t buf[65536];
        uint64_t rem = size;
        while (rem > 0) {
            size_t chunk = rem > sizeof(buf) ? sizeof(buf) : (size_t)rem;
            read_exact(STDIN_FILENO, buf, chunk);
            write_exact(fd, buf, chunk);
            rem -= chunk;
        }
        if (close(fd) != 0)
            die("casper-nar: close error");
        read_pad(size);
        expect_tag(")");
    } else if (strcmp(type, "symlink") == 0) {
        free(type);
        expect_tag("target");
        char *target = read_str(NAR_MAX_TARGET);
        expect_tag(")");
        if (target[0] == '\0' || symlink(target, path) != 0)
            die("casper-nar: failed to create symlink");
        free(target);
    } else if (strcmp(type, "directory") == 0) {
        free(type);
        if (mkdir(path, 0755) != 0)
            die("casper-nar: failed to create directory");
        while (1) {
            char *tag = read_str(NAR_MAX_TAG);
            if (strcmp(tag, ")") == 0) {
                free(tag);
                break;
            }
            if (strcmp(tag, "entry") != 0)
                die("casper-nar: expected entry or ')'");
            free(tag);
            expect_tag("(");
            expect_tag("name");
            char *name = read_str(NAR_MAX_NAME);
            if (name[0] == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0 || strchr(name, '/') != NULL)
                die("casper-nar: invalid entry name");
            expect_tag("node");
            char *child = join_path(path, name);
            restore_node(child, depth + 1);
            free(child);
            free(name);
            expect_tag(")");
        }
    } else {
        die("casper-nar: unknown node type");
    }
}

static int cmp_str(const void *a, const void *b) {
    const char *sa = *(const char *const *)a;
    const char *sb = *(const char *const *)b;
    return strcmp(sa, sb);
}

static void dump_node(const char *path, int depth) {
    if (depth >= NAR_MAX_DEPTH)
        die("casper-nar: max NAR depth exceeded");

    struct stat st;
    if (lstat(path, &st) != 0)
        die("casper-nar: lstat failed");

    if (S_ISREG(st.st_mode)) {
        write_cstr("(");
        write_cstr("type");
        write_cstr("regular");
        if (st.st_mode & S_IXUSR) {
            write_cstr("executable");
            write_cstr("");
        }
        write_cstr("contents");
        uint64_t size = (uint64_t)st.st_size;
        write_u64(size);

        int fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd < 0)
            die("casper-nar: failed to open regular file");
        uint8_t buf[65536];
        uint64_t rem = size;
        while (rem > 0) {
            size_t chunk = rem > sizeof(buf) ? sizeof(buf) : (size_t)rem;
            read_exact(fd, buf, chunk);
            write_exact(STDOUT_FILENO, buf, chunk);
            rem -= chunk;
        }
        close(fd);
        write_pad(size);
        write_cstr(")");
    } else if (S_ISLNK(st.st_mode)) {
        char target[NAR_MAX_TARGET + 1];
        ssize_t len = readlink(path, target, NAR_MAX_TARGET);
        if (len <= 0)
            die("casper-nar: readlink failed");
        write_cstr("(");
        write_cstr("type");
        write_cstr("symlink");
        write_cstr("target");
        write_bytes((const uint8_t *)target, (size_t)len);
        write_cstr(")");
    } else if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (!d)
            die("casper-nar: opendir failed");

        char **names = NULL;
        size_t cnt = 0;
        size_t cap = 0;
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
            if (cnt == cap) {
                size_t ncap = cap ? cap * 2 : 16;
                char **n = (char **)realloc(names, ncap * sizeof(char *));
                if (!n)
                    die("casper-nar: out of memory");
                names = n;
                cap = ncap;
            }
            names[cnt] = strdup(de->d_name);
            if (!names[cnt])
                die("casper-nar: out of memory");
            cnt++;
        }
        closedir(d);

        if (cnt > 1)
            qsort(names, cnt, sizeof(char *), cmp_str);

        write_cstr("(");
        write_cstr("type");
        write_cstr("directory");
        for (size_t i = 0; i < cnt; i++) {
            write_cstr("entry");
            write_cstr("(");
            write_cstr("name");
            write_cstr(names[i]);
            write_cstr("node");
            char *child = join_path(path, names[i]);
            dump_node(child, depth + 1);
            free(child);
            free(names[i]);
            write_cstr(")");
        }
        free(names);
        write_cstr(")");
    } else {
        die("casper-nar: unsupported file type in output");
    }
}

int main(int argc, char **argv) {
    if (argc != 3)
        die("usage: casper-nar <--restore|--dump> <path>");
    if (strcmp(argv[1], "--restore") == 0) {
        expect_tag(NAR_VERSION_MAGIC);
        restore_node(argv[2], 0);
        uint8_t extra;
        ssize_t r = read(STDIN_FILENO, &extra, 1);
        if (r != 0)
            die("casper-nar: trailing bytes after NAR");
        return 0;
    }
    if (strcmp(argv[1], "--dump") == 0) {
        write_cstr(NAR_VERSION_MAGIC);
        dump_node(argv[2], 0);
        return 0;
    }
    die("usage: casper-nar <--restore|--dump> <path>");
    return 1;
}
