#include <cassert>
#include <cstdlib>
#include <sstream>

#include "cmdline.h"

const int FUZZER_OK = 0;
const int FUZZER_FAIL = 1;

class fuzzer
{
public:
  const char *clang_path;
  const char *common_args = "-g";

  fuzzer(const char *clang_path);

  ~fuzzer();

  int do_fuzzing(const char *input_file);
  int do_fuzzing(
    const char *input_file,
    const char *output_file,
    const char *sanitize,
    bool coverage);
  int do_fuzzing(
    const char *input_file,
    const char *output_file,
    const char *sanitize,
    bool coverage,
    const char *include,
    const char *other,
    const char *cmd_args);

  int run_fuzz(std::string output_file, const char *cmd_args);
};
