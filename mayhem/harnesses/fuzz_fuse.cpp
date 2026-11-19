// Fuzz the FUSE wire protocol as mergerfs serves it: the bytes the kernel
// writes to /dev/fuse. The public libfuse API (fuse_new + fuse_loop_mt) is
// pointed at one end of a SOCK_SEQPACKET socketpair instead of /dev/fuse; the
// harness writes the input's messages into the other end, closes it, and the
// real event loop reads, dispatches (fuse_lowlevel.cpp do_*, fuse.cpp
// fuse_lib_*, node table) and runs mergerfs's own operations (src/fuse_*.cpp,
// incl. the /.mergerfs control-file xattr API and ioctls) against two fresh
// scratch branch directories. The operation table is the one mergerfs.cpp's
// _get_fuse_operations() builds (it is static there, so it is repeated here).
//
// Input: a sequence of FUSE requests, each a struct fuse_in_header followed
// by its body; the first must be FUSE_INIT (as the kernel always sends).
// Message boundaries come from each header's len, clamped to what is left;
// the kernel's read() contract is that in->len equals the bytes delivered,
// so len is set to the clamped length.
//
// Per input, everything is fresh: config globals (reset_state.hpp), the
// libfuse handle (fuse_new/fuse_destroy), the socketpair and the branch
// directories (mkdtemp under $TMPDIR, removed afterwards). One read thread and
// no process pool (read-thread-count=1, process-thread-count=-1) so each
// request is handled synchronously, in input order.
//
// Only path-based requests are passed through. A file handle (fh) is the
// address of mergerfs's FileInfo/DirInfo (FileInfo::from_fh casts it back),
// and the kernel only ever echoes fh values the server returned; replies are
// not fed back into the input, so requests that carry an fh (READ, WRITE,
// FLUSH, RELEASE, IOCTL, ..., GETATTR/STATX with FUSE_GETATTR_FH, SETATTR with
// FATTR_FH) are rejected, and so are OPEN/OPENDIR/CREATE/TMPFILE, which would
// hand out handles (and real fds) nothing could release. FORGET and
// BATCH_FORGET are rejected too: the kernel never forgets more lookups than it
// was given, and libfuse asserts that (forget_node) instead of checking it.
//
// Every request body must also have the exact layout the kernel sends for
// its opcode (full fixed-size argument struct, NUL-terminated names, the
// announced xattr value bytes): libfuse reads those without checking the
// message length (see body_ok).
//
// Also not passed through: inputs containing '/' or ".." anywhere in a request
// body, or the strings config / log.file. The kernel only sends single path
// components (never containing '/', never "." or ".."), and the libfuse layer
// trusts that, so such names would make mergerfs touch paths outside the
// scratch branches; config/log.file open other files on disk.
#include "config.hpp"
#include "fuse.h"
#include "fuse_kernel.h"
#include "fuse_cfg.hpp"

#include "fuse_access.hpp"
#include "fuse_bmap.hpp"
#include "fuse_chmod.hpp"
#include "fuse_chown.hpp"
#include "fuse_copy_file_range.hpp"
#include "fuse_create.hpp"
#include "fuse_destroy.hpp"
#include "fuse_fallocate.hpp"
#include "fuse_fchmod.hpp"
#include "fuse_fchown.hpp"
#include "fuse_fgetattr.hpp"
#include "fuse_flush.hpp"
#include "fuse_fsync.hpp"
#include "fuse_fsyncdir.hpp"
#include "fuse_ftruncate.hpp"
#include "fuse_futimens.hpp"
#include "fuse_getattr.hpp"
#include "fuse_getxattr.hpp"
#include "fuse_init.hpp"
#include "fuse_ioctl.hpp"
#include "fuse_link.hpp"
#include "fuse_listxattr.hpp"
#include "fuse_mkdir.hpp"
#include "fuse_mknod.hpp"
#include "fuse_open.hpp"
#include "fuse_opendir.hpp"
#include "fuse_poll.hpp"
#include "fuse_read.hpp"
#include "fuse_readdir.hpp"
#include "fuse_readdir_plus.hpp"
#include "fuse_readlink.hpp"
#include "fuse_release.hpp"
#include "fuse_releasedir.hpp"
#include "fuse_removemapping.hpp"
#include "fuse_removexattr.hpp"
#include "fuse_rename.hpp"
#include "fuse_rmdir.hpp"
#include "fuse_setupmapping.hpp"
#include "fuse_setxattr.hpp"
#include "fuse_statfs.hpp"
#include "fuse_statx.hpp"
#include "fuse_symlink.hpp"
#include "fuse_syncfs.hpp"
#include "fuse_tmpfile.hpp"
#include "fuse_truncate.hpp"
#include "fuse_unlink.hpp"
#include "fuse_utimens.hpp"
#include "fuse_write.hpp"

#include "reset_state.hpp"

// libfuse/lib/fuse.cpp defines fuse_destroy(struct fuse *), while fuse.h
// declares fuse_destroy(void); C++ mangling makes only the definition linkable.
void fuse_destroy(struct fuse *);

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

static void
get_fuse_operations(struct fuse_operations &ops_, const bool nullrw_)
{
  ops_.access          = FUSE::access;
  ops_.bmap            = FUSE::bmap;
  ops_.chmod           = FUSE::chmod;
  ops_.chown           = FUSE::chown;
  ops_.copy_file_range = FUSE::copy_file_range;
  ops_.create          = FUSE::create;
  ops_.destroy         = FUSE::destroy;
  ops_.fallocate       = FUSE::fallocate;
  ops_.fchmod          = FUSE::fchmod;
  ops_.fchown          = FUSE::fchown;
  ops_.fgetattr        = FUSE::fgetattr;
  ops_.flush           = FUSE::flush;
  ops_.fsync           = FUSE::fsync;
  ops_.fsyncdir        = FUSE::fsyncdir;
  ops_.ftruncate       = FUSE::ftruncate;
  ops_.futimens        = FUSE::futimens;
  ops_.getattr         = FUSE::getattr;
  ops_.getxattr        = FUSE::getxattr;
  ops_.init            = FUSE::init;
  ops_.ioctl           = FUSE::ioctl;
  ops_.link            = FUSE::link;
  ops_.listxattr       = FUSE::listxattr;
  ops_.mkdir           = FUSE::mkdir;
  ops_.mknod           = FUSE::mknod;
  ops_.open            = FUSE::open;
  ops_.opendir         = FUSE::opendir;
  ops_.poll            = FUSE::poll;
  ops_.read            = (nullrw_ ? FUSE::read_null : FUSE::read);
  ops_.readdir         = FUSE::readdir;
  ops_.readdir_plus    = FUSE::readdir_plus;
  ops_.readlink        = FUSE::readlink;
  ops_.release         = FUSE::release;
  ops_.releasedir      = FUSE::releasedir;
  ops_.removemapping   = FUSE::removemapping;
  ops_.removexattr     = FUSE::removexattr;
  ops_.rename          = FUSE::rename;
  ops_.rmdir           = FUSE::rmdir;
  ops_.setupmapping    = FUSE::setupmapping;
  ops_.setxattr        = FUSE::setxattr;
  ops_.statfs          = FUSE::statfs;
  ops_.statx           = FUSE::statx;
  ops_.statx_fh        = FUSE::statx_fh;
  ops_.symlink         = FUSE::symlink;
  ops_.syncfs          = FUSE::syncfs;
  ops_.tmpfile         = FUSE::tmpfile;
  ops_.truncate        = FUSE::truncate;
  ops_.unlink          = FUSE::unlink;
  ops_.utimens         = FUSE::utimens;
  ops_.write           = (nullrw_ ? FUSE::write_null : FUSE::write);
}

static bool
acceptable(const uint8_t *data_, size_t size_)
{
  const std::string s(reinterpret_cast<const char *>(data_), size_);
  // Headers carry binary ids/len, so the check covers the whole input: a
  // conservative superset of "a body names a path outside the branches".
  if(s.find('/') != std::string::npos) return false;
  if(s.find("..") != std::string::npos) return false;
  if(s.find("config") != std::string::npos) return false;
  if(s.find("log.file") != std::string::npos) return false;
  return true;
}

// What the first (FUSE_INIT) request negotiated, as far as the body layout of
// later requests depends on it.
struct InitState
{
  uint32_t minor = 0;
};

// Advance past `count_` NUL-terminated strings starting at off_; false if any
// of them is not terminated inside the body (libfuse strlen()s them).
static bool
skip_names(const uint8_t *body_, size_t blen_, size_t &off_, int count_)
{
  for(int i = 0; i < count_; i++)
    {
      if(off_ > blen_) return false;
      const void *nul = memchr(body_ + off_, '\0', blen_ - off_);
      if(!nul) return false;
      off_ = (size_t)((const uint8_t *)nul - body_) + 1;
    }
  return true;
}

// The body must have the layout the kernel always sends for the opcode: the
// opcode's full fixed-size argument struct, then each NUL-terminated name,
// then any trailing data the struct announces. libfuse trusts this layout and
// reads the struct and names without checking the message length, so a short
// body would make it read stale bytes left in its receive buffer by earlier,
// longer messages.
static bool
body_ok(const InitState &st_, uint32_t opcode_, const uint8_t *body_, size_t blen_)
{
  size_t fixed = 0;
  int names = 0;
  switch(opcode_)
    {
    case FUSE_INIT:        fixed = sizeof(fuse_init_in); break;
    case FUSE_READLINK: case FUSE_STATFS: case FUSE_DESTROY: break;
    case FUSE_LOOKUP: case FUSE_UNLINK: case FUSE_RMDIR:
    case FUSE_REMOVEXATTR: names = 1; break;
    case FUSE_SYMLINK:     names = 2; break;
    case FUSE_MKNOD:
      fixed = (st_.minor >= 12) ? sizeof(fuse_mknod_in) : FUSE_COMPAT_MKNOD_IN_SIZE;
      names = 1;
      break;
    case FUSE_MKDIR:       fixed = sizeof(fuse_mkdir_in);   names = 1; break;
    case FUSE_RENAME:      fixed = sizeof(fuse_rename_in);  names = 2; break;
    case FUSE_RENAME2:     fixed = sizeof(fuse_rename2_in); names = 2; break;
    case FUSE_LINK:        fixed = sizeof(fuse_link_in);    names = 1; break;
    case FUSE_GETXATTR:    fixed = sizeof(fuse_getxattr_in); names = 1; break;
    case FUSE_LISTXATTR:   fixed = sizeof(fuse_getxattr_in); break;
    case FUSE_ACCESS:      fixed = sizeof(fuse_access_in);  break;
    case FUSE_INTERRUPT:   fixed = sizeof(fuse_interrupt_in); break;
    case FUSE_GETATTR:     fixed = sizeof(fuse_getattr_in); break;
    case FUSE_STATX:       fixed = sizeof(fuse_statx_in);   break;
    case FUSE_SETATTR:     fixed = sizeof(fuse_setattr_in); break;
    case FUSE_SETXATTR:
      {
        // The struct is 8 bytes (compat) or 16 (FUSE_SETXATTR_EXT, chosen by
        // what INIT and mergerfs negotiated); name + `size` value bytes must
        // fit after it under both layouts.
        if(blen_ < sizeof(fuse_setxattr_in)) return false;
        fuse_setxattr_in in;
        memcpy(&in, body_, sizeof(in));
        for(size_t hdr : {(size_t)FUSE_COMPAT_SETXATTR_IN_SIZE, sizeof(fuse_setxattr_in)})
          {
            size_t off = hdr;
            if(!skip_names(body_, blen_, off, 1)) return false;
            if(blen_ - off < in.size) return false;
          }
        return true;
      }
    default:
      return false;
    }
  if(blen_ < fixed) return false;
  size_t off = fixed;
  return skip_names(body_, blen_, off, names);
}

static bool
allowed_request(InitState &st_, const fuse_in_header &hdr_,
                const uint8_t *body_, size_t blen_)
{
  if(!body_ok(st_, hdr_.opcode, body_, blen_))
    return false;
  // Every opcode that reaches here has a body of at least 4 bytes whenever
  // one of the checks below reads it (body_ok checked the struct size).
  uint32_t flags = 0;
  if(blen_ >= 4)
    memcpy(&flags, body_, 4);
  switch(hdr_.opcode)
    {
    case FUSE_INIT:
      {
        fuse_init_in in;
        memcpy(&in, body_, sizeof(in));
        st_.minor = in.minor;
        return true;
      }
    case FUSE_SETXATTR: case FUSE_GETXATTR: case FUSE_LISTXATTR:
      // The VFS caps xattr sizes at XATTR_SIZE_MAX / XATTR_LIST_MAX (64 KiB)
      // before the request reaches FUSE; libfuse mallocs the size as given.
      return flags <= 65536;
    case FUSE_GETATTR: case FUSE_STATX:
      return !(flags & FUSE_GETATTR_FH);
    case FUSE_SETATTR:
      return !(flags & FATTR_FH);
    default:
      return true;
    }
}

static void
make_branch(const std::string &dir_, int idx_)
{
  std::filesystem::create_directories(dir_ + "/dir/sub");
  std::ofstream(dir_ + "/file" + std::to_string(idx_) + ".txt") << "hello mergerfs " << idx_ << "\n";
  std::ofstream(dir_ + "/common.txt") << "branch " << idx_ << "\n";
  std::ofstream(dir_ + "/dir/inner.txt") << "inner " << idx_ << "\n";
  symlink("common.txt", (dir_ + "/link").c_str());
}

extern "C" int
LLVMFuzzerInitialize(int *, char ***)
{
  signal(SIGPIPE, SIG_IGN);
  return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data_, size_t size_)
{
  if(size_ < sizeof(fuse_in_header) || !acceptable(data_, size_))
    return -1;

  std::vector<std::vector<uint8_t>> msgs;
  InitState st;
  for(size_t off = 0; size_ - off >= sizeof(fuse_in_header); )
    {
      fuse_in_header hdr;
      memcpy(&hdr, data_ + off, sizeof(hdr));
      size_t len = hdr.len;
      if(len < sizeof(hdr)) len = sizeof(hdr);
      if(len > size_ - off) len = size_ - off;
      if(!allowed_request(st, hdr, data_ + off + sizeof(hdr), len - sizeof(hdr)))
        return -1;
      std::vector<uint8_t> msg(data_ + off, data_ + off + len);
      hdr.len = (uint32_t)len;
      memcpy(msg.data(), &hdr, sizeof(hdr));
      msgs.push_back(std::move(msg));
      off += len;
    }

  const char *tmp = getenv("TMPDIR");
  std::string tmpl = std::string((tmp && *tmp) ? tmp : "/tmp") + "/mergerfs-fuse-XXXXXX";
  std::vector<char> tbuf(tmpl.begin(), tmpl.end());
  tbuf.push_back('\0');
  if(!mkdtemp(tbuf.data()))
    return 0;
  const std::string root(tbuf.data());
  make_branch(root + "/b0", 0);
  make_branch(root + "/b1", 1);
  std::filesystem::create_directories(root + "/mnt");

  mayhem_reset_global_config();
  cfg.set("branches", root + "/b0=RW:" + root + "/b1=RW");
  cfg.set("mountpoint", root + "/mnt");
  cfg.set("cache.files", "off");
  fuse_cfg.read_thread_count = 1;
  fuse_cfg.process_thread_count = -1;

  int sv[2];
  if(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0)
    {
      int big = 4 << 20;
      setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
      setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));

      for(const auto &msg : msgs)
        if(send(sv[1], msg.data(), msg.size(), MSG_DONTWAIT | MSG_NOSIGNAL) < 0)
          break;
      shutdown(sv[1], SHUT_WR);

      // Replies are read and discarded so the loop never blocks on a full socket.
      std::thread drain([fd = sv[1]]() {
        std::vector<char> buf(1 << 20);
        while(read(fd, buf.data(), buf.size()) > 0) {}
      });

      struct fuse_operations ops;
      memset(&ops, 0, sizeof(ops));
      get_fuse_operations(ops, cfg.nullrw);

      char arg0[] = "mergerfs";
      char *argv[] = {arg0, nullptr};
      struct fuse_args args = FUSE_ARGS_INIT(1, argv);
      struct fuse *f = fuse_new(sv[0], 1 << 20, &args, &ops);
      if(f)
        {
          fuse_loop_mt(f);
          fuse_destroy(f);
        }
      fuse_opt_free_args(&args);
      close(sv[0]);
      drain.join();
      close(sv[1]);
    }

  std::error_code ec;
  std::filesystem::permissions(root, std::filesystem::perms::owner_all, ec);
  std::filesystem::remove_all(root, ec);
  return 0;
}
