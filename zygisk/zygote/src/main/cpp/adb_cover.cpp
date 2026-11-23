/*
 * ADB runtime cover.
 *
 * The property layer (service.sh + the in-app property hooks) makes every app read
 * init.svc.adbd=stopped, persist.sys.usb.config=mtp and sys.usb.state=mtp. Three surfaces are
 * not properties and stay truthful, so a detector that cross-checks them sees a contradiction:
 *
 *   /dev/socket/adbd        init unlinks it before it publishes "stopped", so its presence
 *                           proves adbd is alive. Applications get EACCES from stat() on the
 *                           inode label; EACCES is reported as "present, label denied", so the
 *                           hook has to answer ENOENT, never EACCES.
 *   /dev/socket listing     File.list() reads the directory; a name with no stat() backing
 *                           degrades the detector to "unknown" instead of "absent".
 *   @jdwp-control           adbd binds this abstract SOCK_SEQPACKET listener itself. connect()
 *                           succeeding (or EACCES from SELinux) is liveness evidence; only
 *                           ECONNREFUSED/ENOENT is read as "no listener".
 *
 * Everything here is a libc interposition in the scoped app process only. It changes nothing
 * for the system, adbd keeps running, and no other process is affected.
 */

#include <jni.h>
#include <dlfcn.h>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <dobby.h>

#include "Logger.h"
#include "self_pin.h"

namespace {

constexpr const char *kSocketDir = "/dev/socket";
constexpr const char *kAdbdPath = "/dev/socket/adbd";
constexpr const char *kAdbdName = "adbd";
constexpr const char *kJdwpName = "jdwp-control";

bool g_installed = false;

using stat_fn = int (*)(const char *, struct stat *);
using fstatat_fn = int (*)(int, const char *, struct stat *, int);
using statx_fn = int (*)(int, const char *, int, unsigned int, struct statx *);
using readdir_fn = struct dirent *(*)(DIR *);
using readdir64_fn = struct dirent64 *(*)(DIR *);
using connect_fn = int (*)(int, const struct sockaddr *, socklen_t);
using dirfd_fn = int (*)(DIR *);

stat_fn orig_stat = nullptr;
stat_fn orig_lstat = nullptr;
fstatat_fn orig_fstatat = nullptr;
statx_fn orig_statx = nullptr;
readdir_fn orig_readdir = nullptr;
readdir64_fn orig_readdir64 = nullptr;
connect_fn orig_connect = nullptr;
dirfd_fn real_dirfd = nullptr;

/** "/dev/socket/adbd" and "/dev/socket//adbd/" alike. */
bool is_adbd_path(const char *path) {
    if (path == nullptr) return false;
    const size_t prefix = strlen(kSocketDir);
    if (strncmp(path, kSocketDir, prefix) != 0) return false;
    const char *rest = path + prefix;
    while (*rest == '/') rest++;
    const size_t name_len = strlen(kAdbdName);
    if (strncmp(rest, kAdbdName, name_len) != 0) return false;
    rest += name_len;
    while (*rest == '/') rest++;
    return *rest == '\0';
}

/** True when this descriptor is an open handle for /dev/socket. */
bool fd_is_socket_dir(int fd) {
    if (fd < 0) return false;
    char link[64];
    char target[256];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    const ssize_t n = readlink(link, target, sizeof(target) - 1);
    if (n <= 0) return false;
    target[n] = '\0';
    return strcmp(target, kSocketDir) == 0;
}

bool dir_is_socket_dir(DIR *dir) {
    if (dir == nullptr || real_dirfd == nullptr) return false;
    return fd_is_socket_dir(real_dirfd(dir));
}

/** Relative lookups ("adbd") are resolved against the descriptor's directory. */
bool denied_relative(int dirfd_value, const char *path) {
    if (path == nullptr || path[0] == '/') return false;
    if (strcmp(path, kAdbdName) != 0) return false;
    return dirfd_value == AT_FDCWD ? false : fd_is_socket_dir(dirfd_value);
}

int my_stat(const char *path, struct stat *buf) {
    if (is_adbd_path(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat(path, buf);
}

int my_lstat(const char *path, struct stat *buf) {
    if (is_adbd_path(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat(path, buf);
}

int my_fstatat(int dirfd_value, const char *path, struct stat *buf, int flags) {
    if (is_adbd_path(path) || denied_relative(dirfd_value, path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_fstatat(dirfd_value, path, buf, flags);
}

int my_statx(int dirfd_value, const char *path, int flags, unsigned int mask,
             struct statx *buf) {
    if (is_adbd_path(path) || denied_relative(dirfd_value, path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_statx(dirfd_value, path, flags, mask, buf);
}

struct dirent *my_readdir(DIR *dir) {
    struct dirent *entry;
    const bool socket_dir = dir_is_socket_dir(dir);
    do {
        entry = orig_readdir(dir);
        if (entry == nullptr) return nullptr;
    } while (socket_dir && strcmp(entry->d_name, kAdbdName) == 0);
    return entry;
}

struct dirent64 *my_readdir64(DIR *dir) {
    struct dirent64 *entry;
    const bool socket_dir = dir_is_socket_dir(dir);
    do {
        entry = orig_readdir64(dir);
        if (entry == nullptr) return nullptr;
    } while (socket_dir && strcmp(entry->d_name, kAdbdName) == 0);
    return entry;
}

/** Only the one abstract name adbd binds; every other connect passes through untouched. */
int my_connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (address != nullptr && address->sa_family == AF_UNIX &&
        length > static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path) + 1)) {
        const auto *un = reinterpret_cast<const struct sockaddr_un *>(address);
        if (un->sun_path[0] == '\0' && strcmp(un->sun_path + 1, kJdwpName) == 0) {
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return orig_connect(fd, address, length);
}

template <typename Fn>
bool hook_symbol(const char *symbol, void *replacement, Fn *original) {
    auto *target = reinterpret_cast<void *>(dlsym(RTLD_DEFAULT, symbol));
    if (target == nullptr) {
        LOGD("%s not exported, skipped", symbol);
        return false;
    }
    if (DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(replacement),
                  reinterpret_cast<dobby_dummy_func_t *>(original)) != 0) {
        LOGE("failed to hook %s", symbol);
        return false;
    }
    return true;
}

}  // namespace

extern "C"
JNIEXPORT jint JNICALL
Java_com_strawing_duckusb_zygote_hook_Native_installAdbCover(
        JNIEnv *, jobject, jboolean cover_inode, jboolean cover_listing, jboolean cover_jdwp) {
    if (g_installed) return 1;
    if (!pin_self()) {
        LOGE("module image could not be pinned (%s), adb cover not armed", pin_self_error());
        return 0;
    }

    int armed = 0;

    if (cover_inode) {
        if (hook_symbol("stat", reinterpret_cast<void *>(my_stat), &orig_stat)) armed++;
        if (hook_symbol("lstat", reinterpret_cast<void *>(my_lstat), &orig_lstat)) armed++;
        if (hook_symbol("fstatat", reinterpret_cast<void *>(my_fstatat), &orig_fstatat)) armed++;
        // statx is API 30+; an absent symbol is not an error.
        hook_symbol("statx", reinterpret_cast<void *>(my_statx), &orig_statx);
    }

    if (cover_listing) {
        real_dirfd = reinterpret_cast<dirfd_fn>(dlsym(RTLD_DEFAULT, "dirfd"));
        // readdir64 is an alias of readdir on LP64; hook whichever are distinct.
        void *plain = dlsym(RTLD_DEFAULT, "readdir");
        void *wide = dlsym(RTLD_DEFAULT, "readdir64");
        if (wide != nullptr) {
            orig_readdir = reinterpret_cast<readdir_fn>(plain);
            if (hook_symbol("readdir64", reinterpret_cast<void *>(my_readdir64), &orig_readdir64)) {
                armed++;
            }
        }
        if (plain != nullptr && plain != wide) {
            if (hook_symbol("readdir", reinterpret_cast<void *>(my_readdir), &orig_readdir)) armed++;
        } else if (plain != nullptr && orig_readdir == nullptr) {
            orig_readdir = orig_readdir64 == nullptr
                                   ? nullptr
                                   : reinterpret_cast<readdir_fn>(orig_readdir64);
        }
    }

    if (cover_jdwp) {
        if (hook_symbol("connect", reinterpret_cast<void *>(my_connect), &orig_connect)) armed++;
    }

    if (armed == 0) return 0;
    g_installed = true;
    LOGD("adb runtime cover armed: %d hooks (inode=%d listing=%d jdwp=%d)", armed, cover_inode,
         cover_listing, cover_jdwp);
    return armed;
}
