// Fuzz the mergerfs config-file parser: Config::from_stream, the code that
// reads `mergerfs -o config=FILE` (and, value by value, the runtime
// user.mergerfs.* xattr API). Every key's from_string() runs: branch specs
// (+>, -<, =RW, minfreespace, globs), size suffixes (from_string.cpp,
// num.cpp), policies, enums, ints and bools.
//
// Three keys are not passed through because they reach outside the input:
//   config    opens and parses another file from disk (recursively)
//   log.file  opens an arbitrary path for append (writes outside scratch)
//   debug     redirects libfuse's debug output to the log.file stream
// The filter uses the same key extraction Config::set() does (trim of the
// part before the first '=', '_' -> '-'), so it cannot be bypassed by
// spelling. Config::set does no unescaping, so the lines given to the parser
// are exactly the lines checked here.
#include "config.hpp"
#include "str.hpp"

#include "reset_state.hpp"

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

static bool
blocked_key(const std::string &line_)
{
  auto [key, val] = str::splitkv(line_, '=');
  key = str::trim(key);
  key = str::replace(key, '_', '-');
  return key == "config" || key == "log.file" || key == "debug";
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data_, size_t size_)
{
  std::string input(reinterpret_cast<const char *>(data_), size_);
  std::istringstream in(input);
  std::string filtered;
  std::string line;

  while(std::getline(in, line, '\n'))
    {
      if(blocked_key(str::trim(line)))
        continue;
      filtered += line;
      filtered += '\n';
    }

  mayhem_reset_global_config();

  std::istringstream is(filtered);
  cfg.from_stream(is);
  mayhem_dump_config();

  return 0;
}
