/*******************************************************************\

Module:

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#if defined(_WIN32)
#define EX_OK 0
#define EX_USAGE 1
#else
#include <sysexits.h>
#endif

#include <util/cmdline.h>
#include <util/parseoptions.h>
#include <util/signal_catcher.h>
#include <boost/program_options.hpp>
#include "fuzzing.h"

parseoptions_baset::parseoptions_baset(
  const struct group_opt_templ *opts,
  int argc,
  const char **argv,
  const messaget &msg)
  : cmdline(msg)
{
  exception_occured = cmdline.parse(argc, argv, opts);
}

void parseoptions_baset::help()
{
}

int parseoptions_baset::main()
{
  if(exception_occured)
  {
    return EX_USAGE;
  }
  if(cmdline.isset("help") || cmdline.isset("explain"))
  {
    help();
    return EX_OK;
  }

  if(cmdline.isset("fuzz"))
  {
    int ret;
    bool coverage = false;
    const char *output = cmdline.getval("fuzz-output");
    const char *sanitize = cmdline.getval("fuzz-sanitize");
    const std::list<std::string> &compile_args =
      cmdline.get_values("fuzz-compile");
    const std::list<std::string> &run_args = cmdline.get_values("fuzz-run");

    if(cmdline.args.size() != 1)
    {
      printf("Please provide one program to preprocess.\n");
      return EX_USAGE;
    }
    std::string input = cmdline.args[0];

    fuzzer f = fuzzer(cmdline.getval("fuzz-clang"));

    if(cmdline.isset("fuzzing-coverage"))
    {
      coverage = true;
    }

    std::string compile_args_full = std::string("");
    std::string run_args_full = std::string("");

    if(!compile_args.empty())
    {
      for(std::list<std::string>::const_iterator elem = compile_args.begin();
          elem != compile_args.end();
          elem++)
      {
        compile_args_full = compile_args_full + *elem;
        compile_args_full = compile_args_full + " ";
      }
    }

    if(!run_args.empty())
    {
      for(std::list<std::string>::const_iterator elem = run_args.begin();
          elem != run_args.end();
          elem++)
      {
        run_args_full = run_args_full + *elem;
        run_args_full = run_args_full + " ";
      }
    }

    ret = f.do_fuzzing(
      input.c_str(),
      output,
      sanitize,
      coverage,
      NULL,
      compile_args_full.c_str(),
      run_args_full.c_str());
    return ret;
  }

  // install signal catcher
  install_signal_catcher();
  return doit();
}
