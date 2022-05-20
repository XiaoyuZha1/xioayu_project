#include <stdio.h>
 
int main(void)
{
  float a = 1.0f;
  long double b = 5567.765434376l;

  printf("15.0     = %a\n", 15.0);
  printf("0x1.ep+3 = %f\n", 0x1.ep+3);

  // Constants outside the range of type double.
  printf("+2.0e+308 --> %g\n",  2.0e+308);
  printf("+1.0e-324 --> %g\n",  1.0e-324);
  printf("-1.0e-324 --> %g\n", -1.0e-324);
  printf("-2.0e+308 --> %g\n", -2.0e+308);
}
