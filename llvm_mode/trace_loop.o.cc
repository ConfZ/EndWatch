//
// Created by zy on 2022/4/7.
//

#include <functional>
#include <iostream>
#include <boost/functional/hash.hpp>
#include <signal.h>
extern "C"{
std::size_t  boolHash(bool i){
    return std::hash<bool>{}(i);
}

std::size_t  charHash(unsigned char i){
    return std::hash<unsigned char>{}(i);
}

std::size_t  i16Hash(unsigned short i){
    return std::hash<unsigned short>{}(i);
}

std::size_t  i32Hash(unsigned int i){
    return std::hash<unsigned int>{}(i);
}


std::size_t  i64Hash(unsigned long i){
    return std::hash<unsigned long>{}(i);
}

std::size_t  stringHash(char* s){
    std::string str = s;

    return std::hash<std::string>{}(str);
}
std::size_t  ptrHash(uintptr_t i){
    return std::hash<uintptr_t>{}(i);
}

std::size_t  floatHash(float i){
    return std::hash<float>{}(i);
}
std::size_t  doubleHash(double i){
    return std::hash<double>{}(i);
}
std::size_t  longDoubleHash(long double i){
    return std::hash<long double>{}(i);
}
std::size_t hashCombine(unsigned long* arr, int size){
    std::size_t seed = 0;
    for(int i = 0; i < size; ++i){

        std::size_t t = *(arr + i);
        boost::hash_combine(seed, t);
    }
    return seed;
}
void _infiniteLoop(void){
    std::cout<<"infinite loop!"<<'\n';
    raise(SIGSEGV);
}
void _check(unsigned long* oldArr, unsigned long newVal, unsigned int times, unsigned int* instrumentNum){
    if (times == 0 or (*instrumentNum) == 0){
        *(oldArr) = newVal;
        (*instrumentNum)++;
        return;
    }
    //check whether the variable exists
    for (int i = 0; i < (*instrumentNum); ++i){
        if( *(oldArr + i) == newVal){
            std::cout<<"infinite loop!"<<'\n';
            raise(SIGSEGV);
        }
    }

    if ((*instrumentNum) < 1000){
        if (times<1000&& times%100==0)
            *(oldArr + (*instrumentNum)) = newVal;
        if ( times > 1000 && times <= 10000 && times%500 == 0)
            *(oldArr + (*instrumentNum)) = newVal;
        if (times > 10000 && times%1000 == 0)
            *(oldArr + (*instrumentNum)) = newVal;
        if (times > 20000 && times%5000 == 0)
            *(oldArr + (*instrumentNum)) = newVal;
        (*instrumentNum)++;
    }
}
}