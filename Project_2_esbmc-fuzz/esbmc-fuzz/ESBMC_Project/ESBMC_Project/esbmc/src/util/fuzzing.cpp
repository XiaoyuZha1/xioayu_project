#include <cassert>
#include <cstdlib>
#include <sstream>
#include <list>
#include <iostream>

#include "fuzzing.h"

fuzzer::fuzzer(const char *clang_path)
{
  this->clang_path = clang_path;
}

fuzzer::~fuzzer(){};

int fuzzer::run_fuzz(std::string output_file, const char *cmd_args)
{
  int ret;
  if(output_file.size() < 1)
  {
    printf("wrong output file");
    return -1;
  }
  if(output_file[0] != '/' && output_file[0] != '.' && output_file[0] != '~')
  {
    std::string run_cmd =
      std::string("./") + output_file + " " + std::string(cmd_args);
    std::cout << run_cmd << std::endl;
    ret = system(run_cmd.c_str());
  }
  else
  {
    std::string run_cmd = output_file + " " + std::string(cmd_args);
    std::cout << run_cmd << std::endl;
    ret = system(run_cmd.c_str());
  }
  return ret;
}

int fuzzer::do_fuzzing(
  const char *input_file,
  const char *output_file,
  const char *sanitize,
  bool coverage,
  const char *include,
  const char *other,
  const char *cmd_args)
{
  std::list<std::string> args = std::list<std::string>();
  std::string of = std::string("./a.out");

  if(this->clang_path == nullptr)
  {
    printf("can not find a clang binary.\n");
    return FUZZER_FAIL;
  }
  if(input_file == nullptr)
  {
    printf("must have a input file.\n");
    return FUZZER_FAIL;
  }

  args.push_back(this->clang_path);
  args.push_back(this->common_args);

  std::string sanitize_arg = std::string("-fsanitize=fuzzer");

  if(sanitize != nullptr)
  {
    sanitize_arg = sanitize_arg + "," + std::string(sanitize);
  }
  args.push_back(sanitize_arg);

  if(coverage)
  {
    std::string coverage_arg =
      std::string("-fsanitize-coverage=trace-pc-guard");
    args.push_back(coverage_arg);
  }

  if(output_file != nullptr)
  {
    of = std::string(output_file);
    std::string output_arg = std::string("-o ") + of;
    args.push_back(output_arg);
  }

  if(include != nullptr)
  {
    std::string include_arg = std::string("-I ") + std::string(include);
    args.push_back(include_arg);
  }

  if(other != nullptr)
  {
    args.push_back(std::string(other));
  }

  args.push_back(input_file);

  std::string cmd;
  for(std::list<std::string>::iterator elem = args.begin(); elem != args.end();
      elem++)
  {
    cmd = cmd + *elem + " ";
  }
  std::cout << cmd << std::endl;
  int ret = system(cmd.c_str());

  if(ret != 0)
  {
    return ret;
  }

  ret = fuzzer::run_fuzz(of, cmd_args);
  return ret;
}

int fuzzer::do_fuzzing(
  const char *input_file,
  const char *output_file,
  const char *sanitize,
  bool coverage)
{
  return fuzzer::do_fuzzing(
    input_file, output_file, sanitize, coverage, NULL, NULL, NULL);
}

int fuzzer::do_fuzzing(const char *input_file)
{
  return fuzzer::do_fuzzing(input_file, NULL, NULL, false, NULL, NULL, NULL);
}