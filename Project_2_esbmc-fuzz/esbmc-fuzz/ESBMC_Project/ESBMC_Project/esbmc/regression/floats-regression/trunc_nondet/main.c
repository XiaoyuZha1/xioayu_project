#include <math.h>
#include <fenv.h>

extern void __VERIFIER_assume(int);
extern void __VERIFIER_error() __attribute__ ((__noreturn__));
void __VERIFIER_assert(int cond) { if (!(cond)) { ERROR: __VERIFIER_error(); } return; }

int main(void)
{
  double d;
  __VERIFIER_assume(!isinf(d));
  __VERIFIER_assume(!isnan(d));

  int save_round = fegetround();
  fesetround(FE_TOWARDZERO);
  double result = rint(d);
  fesetround(save_round);

  __VERIFIER_assert(trunc(d) == result);

  double d1;
  __VERIFIER_assume(isinf(d1));
  __VERIFIER_assert(isinf(trunc(d1)));

  double d2;
  __VERIFIER_assume(isinf(d2));
  __VERIFIER_assert(isinf(trunc(d2)));

  return 0;
}

