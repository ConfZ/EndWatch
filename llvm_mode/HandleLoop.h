//
// Created by zy on 2022/1/9.
//

#ifndef AFL_HANDLELOOP_H
#define AFL_HANDLELOOP_H
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Analysis/LoopInfo.h"
#include <iostream>
using namespace llvm;
class HandleLoop {
public:
    Loop* L;
    HandleLoop(Loop* l): L(l){
    }
    void zy();
};


#endif //AFL_HANDLELOOP_H
