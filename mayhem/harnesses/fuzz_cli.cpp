// Fuzz mergerfs's command-line handling: options::parse() (src/option_parser.cpp),
// which runs libfuse's fuse_opt_parse() tokeniser (comma splitting and
// backslash unescaping of -o lists) and feeds every option to Config::set(),
// treats non-options as branches/mountpoint, and builds the fsname.
// This is the same call mergerfs's _main() makes before mounting.
//
// Input: NUL-separated argv tokens (argv[0] = "mergerfs" is prepended).
//
// Not passed through (they reach outside the input):
//   -h/--help/-v/-V/--version   call exit(0) by design (_option_processor's
//   MERGERFS_OPT_HELP/VERSION keys). fuse_opt matches these keys as whole
//   argv tokens and also as items of a -o list ("-o x,-V", "-o-V"), so every
//   comma-separated item of every token, with backslashes removed and a
//   leading -o stripped, is checked against them.
//   any input naming config or log.file  (opens/writes files on disk; since
//   fuse_opt unescapes '\x' -> 'x' the check is done on the bytes with
//   backslashes removed, so escapes cannot hide the key)
#include "config.hpp"
#include "fuse.h"
#include "fuse_opt.h"
#include "option_parser.hpp"

#include "reset_state.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static bool
names_file_option(const std::string &in_)
{
  std::string s;
  for(char c : in_)
    if(c != '\\')
      s += c;
  return (s.find("config") != std::string::npos ||
          s.find("log.file") != std::string::npos);
}

static bool
is_exit_key(const std::string &s_)
{
  return (s_ == "-h" || s_ == "--help" || s_ == "-v" || s_ == "-V" ||
          s_ == "--version");
}

// True if fuse_opt_parse could match this argv token (or one of its -o list
// items) to MERGERFS_OPT_HELP / MERGERFS_OPT_VERSION.
static bool
reaches_exit(const std::string &tok_)
{
  std::string s;
  for(char c : tok_)
    if(c != '\\')
      s += c;
  std::vector<std::string> cands = {s};
  if(s.compare(0, 2, "-o") == 0)
    cands.push_back(s.substr(2));
  for(const auto &c : cands)
    {
      if(is_exit_key(c))
        return true;
      size_t b = 0;
      for(size_t i = 0; i <= c.size(); i++)
        if(i == c.size() || c[i] == ',')
          {
            if(is_exit_key(c.substr(b, i - b)))
              return true;
            b = i + 1;
          }
    }
  return false;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data_, size_t size_)
{
  std::string input(reinterpret_cast<const char *>(data_), size_);
  if(names_file_option(input))
    return -1;

  std::vector<std::string> toks;
  toks.emplace_back("mergerfs");
  size_t start = 0;
  for(size_t i = 0; i <= input.size(); i++)
    {
      if(i == input.size() || input[i] == '\0')
        {
          std::string t = input.substr(start, i - start);
          if(reaches_exit(t))
            return -1;
          if(i != input.size() || !t.empty())
            toks.push_back(t);
          start = i + 1;
        }
    }

  mayhem_reset_global_config();

  std::vector<char *> argv;
  for(auto &t : toks)
    argv.push_back(strdup(t.c_str()));
  argv.push_back(nullptr);

  fuse_args args = FUSE_ARGS_INIT((int)toks.size(), argv.data());
  options::parse(&args);
  mayhem_dump_config();
  fuse_opt_free_args(&args);

  for(char *p : argv)
    free(p);

  return 0;
}
