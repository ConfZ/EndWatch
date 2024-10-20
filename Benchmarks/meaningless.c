#include "../config.h"
#include "../types.h"
#include "../debug.h"
int func(dir){
   ....
}
int main(){
  u8 *dir;
  ...
  ...
  int i=func(dir);
  While(i<100){
      if(i<50)
        {i=i+1;}
      else
        {i=i-1;}
  }
  ...
  ...
  return 0 
}
