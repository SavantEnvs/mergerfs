// Per-input reset of mergerfs's process-global configuration.
//
// mergerfs keeps its whole runtime configuration in two globals: `Config cfg`
// (src/config.cpp) and libfuse's `fuse_cfg_t fuse_cfg` (fuse_cfg.cpp). Both
// are mutated by option/config parsing, so each input re-constructs them in
// place: an input's result then depends only on that input.
#pragma once

#include "config.hpp"
#include "fuse_cfg.hpp"

#include <new>

static inline void
mayhem_reset_global_config()
{
  cfg.~Config();
  new (&cfg) Config();
  fuse_cfg.~fuse_cfg_t();
  new (&fuse_cfg) fuse_cfg_t();
}

// Render every config value through its to_string() and list the keys the
// way the /.mergerfs listxattr control-file API does.
static inline void
mayhem_dump_config()
{
  ssize_t sz = cfg.keys_listxattr_size();
  if(sz > 0)
    {
      std::string list(sz, '\0');
      cfg.keys_listxattr(list.data(), list.size());
      for(size_t i = 0; i < list.size(); )
        {
          const char *k = list.c_str() + i;
          size_t len = strnlen(k, list.size() - i);
          std::string key(k, len);
          i += len + 1;
          if(key.size() > sizeof("user.mergerfs.") - 1)
            {
              std::string val;
              cfg.get(key.substr(sizeof("user.mergerfs.") - 1), &val);
            }
        }
    }
  for(const auto &e : cfg.errs)
    (void)e.to_string();
}
