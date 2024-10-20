#include "../config.h"
#include "../types.h"
#include "../debug.h"
int func(file *dir){
   ....
}
int main(){
  file *dir;
  ...
  ...
  int i=func(dir);
  While(i<100){
     Check(i);
     Record(i);
      if(i<50)
        {i=i+1;}
      else
        {i=i-1;}
  }
  ...
  ...
  return 0 
}
