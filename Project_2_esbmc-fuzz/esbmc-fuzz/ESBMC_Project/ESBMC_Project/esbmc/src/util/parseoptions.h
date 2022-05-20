/*******************************************************************\

Module:

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#ifndef DBOX_PARSEOPTIONS_H

#define DBOX_PARSEOPTIONS_H

#include <string>
#include <util/cmdline.h>

class parseoptions_baset
{
public:
  parseoptions_baset(
    const struct group_opt_templ *opts,
    int argc,
    const char **argv,
    const messaget &msg);

  cmdlinet cmdline;
  virtual void help();
  virtual int doit() = 0;
  virtual int main();
  virtual ~parseoptions_baset() = default;

private:
  bool exception_occured;
};

#endif
