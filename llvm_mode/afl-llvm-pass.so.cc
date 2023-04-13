#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Analysis/ScalarEvolution.h"
//#include "HandleLoop.h"
//#include "PDA.h"
//#include "test.h"
#include "stack"
#include <llvm/Analysis/CFG.h>
#include <llvm/IR/InstVisitor.h>
#include <set>
#include <fstream>
#include <map>
using namespace llvm;
using namespace std;

#define UNHANDLETY "Unsupported Type"

//Pass init
namespace {
    class LoopInstrument : public FunctionPass {

    public:

        static char ID;
        LoopInstrument() : FunctionPass(ID) {
        }

        bool runOnFunction(Function& F) override;
        void getAnalysisUsage(AnalysisUsage &AU) const override {
            AU.addRequired<LoopInfoWrapperPass>();
//            AU.addRequired<CallGraphWrapperPass>();
//            AU.addRequired<ScalarEvolutionWrapperPass>();
        }
         StringRef getPassName() const override {
          return "Loop Fuzzer Instrumentation";
         }

    };

}

char LoopInstrument::ID = 0;

/*-----------------------------------------------------------*/
namespace {

    class AFLCoverage : public ModulePass {

    public:

        static char ID;
        AFLCoverage() : ModulePass(ID) { }

        bool runOnModule(Module &M) override;
        void getAnalysisUsage(AnalysisUsage &AU) const override {
        }
    };
}
char AFLCoverage::ID = 1;

/**The AFL part **/
bool AFLCoverage::runOnModule(Module &M) {

        string Str;
        raw_string_ostream OS(Str);
        M.print(OS, nullptr);
        ofstream outfile;
        outfile.open("/home/zy/Documents/workplace/fuzzing_for_loop/ToFuzz/tool/AFL-LOOP/llvm-info/Module_out.ll");
        outfile << Str;
        outfile.close();
    LLVMContext &C = M.getContext();

    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

    /* Show a banner */

    char be_quiet = 0;

    if (isatty(2) && !getenv("AFL_QUIET")) {

        SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

    } else be_quiet = 1;

    /* Decide instrumentation ratio */

    char* inst_ratio_str = getenv("AFL_INST_RATIO");
    unsigned int inst_ratio = 100;

    if (inst_ratio_str) {

        if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
            inst_ratio > 100)
            FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

    }

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
            new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                               GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
            M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
            0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

    /* Instrument all the things! */

    int inst_blocks = 0;

    for (auto &F : M)
        for (auto &BB : F) {

            BasicBlock::iterator IP = BB.getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));

            if (AFL_R(100) >= inst_ratio) continue;

            /* Make up cur_loc */

            unsigned int cur_loc = AFL_R(MAP_SIZE);

            ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

            /* Load prev_loc */

            LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc->getType()->getPointerElementType(), AFLPrevLoc);
            PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

            /* Load SHM pointer */

            LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr->getType()->getPointerElementType(), AFLMapPtr);
            MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *MapPtrIdx =
                    IRB.CreateGEP(MapPtr->getType()->getPointerElementType(), MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

            /* Update bitmap */

            LoadInst *Counter = IRB.CreateLoad(MapPtrIdx->getType()->getPointerElementType(), MapPtrIdx);
            Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
            IRB.CreateStore(Incr, MapPtrIdx)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

            /* Set prev_loc to cur_loc >> 1 */

            StoreInst *Store =
                    IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
            Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

            inst_blocks++;

        }

    /* Say something nice. */

    if (!be_quiet) {

        if (!inst_blocks) WARNF("No instrumentation targets found.");
        else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
                 inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
                              ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
                               "ASAN/MSAN" : "non-hardened"), inst_ratio);

    }

    return true;

}
/*-----------------------------------------------------------*/

/**Reversed Path Visitor**/



















/**Path visitor**/
class Visitor : public InstVisitor<Visitor> {
    vector<BasicBlock *> path;
    map<Value *, set < Value * >> VMap;
    map<Value *, set< Value * >> instMap;
    map<Value*, Value*> ptrStack;
    BasicBlock* predBlk;

//    vector<Value*> variables;
//    void getGlobalsUsedByFunction(const Function &F, set<GlobalVariable*> &Globals) {
//        for (auto BasicBlock &BB : F)
//            for (auto &I : BB)
//                for (auto *Op : I.operands())
//                    if (auto G = dyn_cast<GlobalVariable>(*Op))
//                        Globals.insert(G);
//    }
    set<Value*> getValuesFromStack(Value* v){
//        outs()<<"getValuesFromStack"<<'\n';
        if (Instruction *ins = dyn_cast<Instruction>(v)){
            auto it = VMap.find(v);
            if (it == VMap.end())
                return set<Value*>({v});
            else
                return it->second;
        } else
            return set<Value*>({v});
    }
    bool isBeforeCurBlk(BasicBlock* pre, BasicBlock* cur) {
//        outs()<<"isBeforeCurBlk"<<'\n';
        auto isInPath = std::find(path.begin(), path.end(), pre);
        if (isInPath != path.end()) {
            auto isBeforeCurBlk = std::find(isInPath, path.end(), cur);
            if (isBeforeCurBlk != path.end()) return true;
        }
        return false;
    }
public:
    map<Value*, Value*> ptrLink;
    set<Value*> infectedPtrSet;
    map<Value *, set < Value *>> getVMap(){
        return VMap;
    }
    map<Value*, set<Value*>> getInstMap(){
        return instMap;
    }

    Visitor(vector<BasicBlock *> path, BasicBlock* pred = nullptr):
    path(path), predBlk(pred){}


    void link(){
        for (auto &BB: path){
            for (auto &I: *BB){
                visit(&I);
            }
        }
    }
    set<Value*> recurseVisit(Value* I, bool &isVisited, set<LoadInst*>& loads){
        auto iter = instMap.find(I);
        if(!instMap.count(I)) return set<Value*>({I});
        set<Value*> results;
//        outs()<< "checkPoint5:"<<"\n";
//        I->dump();
        set<Value*> leaves;
        isVisited = true;

        if (LoadInst* loadVar = dyn_cast<LoadInst>(I)){
            loads.insert(loadVar);
            auto thePtrs = getValuesFromStack(loadVar->getPointerOperand());
//            outs()<<"the pointers:\n";
//            for(auto res: thePtrs)
//                res->dump();
            leaves.insert(thePtrs.begin(), thePtrs.end());
        }
        else if(auto ee = dyn_cast<ExtractElementInst>(I)){
            leaves.insert(ee->getIndexOperand());
        } else{
            leaves.insert(iter->second.begin(), iter->second.end());
        }
//        outs()<< "checkPoint6:"<<"\n";
        for (auto leaf: leaves){
//            outs()<<"The leaves:\n";
            auto recursiveResults = recurseVisit(leaf, isVisited, loads);
//            outs()<<"Related leaves:\n";
//            for (auto l: recursiveResults)
//                l->dump();
            results.insert(recursiveResults.begin(), recursiveResults.end());
        }
//        outs()<< "checkPoint7:"<<"\n";
        return results;
    }

    set<Value*> getRelatedValue(Value* V){
//        outs()<<"getRelated"<<'\n';
        set<Value*> relatedValues = getValuesFromStack(V);
        set<Value*> relatedVariables;
        for(Value* v : relatedValues){

            if (isa<ConstantData>(v)) continue;
            if (isa<GetElementPtrInst>(v)){
            } else relatedVariables.insert(v);
        }
        return relatedVariables;
    }

//    SmallPtrSet<Value*, 8> getRelatedOuterValue(Value* val, Loop* targetLoop){
//
//        set<Value*> relatedVals = getValuesFromStack(val);
//        SmallPtrSet<Value*, 8> outerVals;
//        for(auto V : relatedVals){
//            if(auto I = dyn_cast<Instruction>(V)){
//                if(!targetLoop->contains(I->getParent())){
//                    outerVals.insert(I);
//                }
//            }
//
//        }
//        return outerVals;
//    }

    //------begin visit------------
    void visitBinaryOperator(BinaryOperator &I){
//        outs()<<"visitBinaryOperator"<<'\n';
        unsigned int opNumber = I.getNumOperands();
        set<Value*> ops;
        set<Value*> opins;
        for (unsigned int i = 0; i < opNumber; ++i){
            auto relatedVal = getRelatedValue(I.getOperand(i));
            ops.insert(relatedVal.begin(), relatedVal.end());
            opins.insert(I.getOperand(i));
        }
        VMap.insert(make_pair(&I, ops));
        instMap.insert(make_pair(&I, opins));
    };

    void visitPHINode(PHINode &PN) {
//        outs()<<"visitPHINode"<<'\n';
//        outs()<<"the map before PHINode:\n";
//        for(auto IM:instMap){
//            outs()<<"the first value:\n";
//            IM.first->dump();
//            outs()<<"the second value:\n";
//            for(auto i:IM.second){
//                i->dump();
//            }
//        }
        if (predBlk){
//            outs()<<"inserted 1\n";
            Value* preValue = PN.getIncomingValueForBlock(predBlk);
//            preValue->dump();
            set < Value * > subOps = getValuesFromStack(preValue);
            VMap.insert(make_pair(&PN, subOps));
            instMap.insert(make_pair(&PN, set<Value*>({preValue})));
            return;
        }
        BasicBlock* curBlk = PN.getParent();
//        outs()<<"currentBlk:\n"<<curBlk->getName()<<'\n';

        for (auto preBlk = PN.block_begin(); preBlk != PN.block_end(); preBlk++){
//            outs()<<"preBlks:" <<(*preBlk)->getName()<<'\n';
            auto isInPath = std::find(path.begin(), path.end(), *preBlk);
//            outs()<<(*preBlk)->getName()<<'\n';
            if (isInPath != path.end() and (*preBlk) != curBlk){
                auto isBeforeCurBlk = std::find(isInPath, path.end(), curBlk);
                if (isBeforeCurBlk != path.end()) {
//                    outs()<<"inserted 2\n";
                        Value *preValue = PN.getIncomingValueForBlock(*preBlk);
                        set < Value * > subOps = getValuesFromStack(preValue);
                        VMap.insert(make_pair(&PN, subOps));
                        instMap.insert(make_pair(&PN, set<Value*>({preValue})));

//                    outs()<<"the map after inserted PHINode:\n";
//                    for(auto IM:instMap){
//                        outs()<<"the first value:\n";
//                        IM.first->dump();
//                        outs()<<"the second value:\n";
//                        for(auto i:IM.second){
//                            i->dump();
//                        }
//                    }
                        return;
                    }
                    }
                }
//        outs()<<"the map after PHINode:\n";
//        for(auto IM:instMap){
//            outs()<<"the first value:\n";
//            IM.first->dump();
//            outs()<<"the second value:\n";
//            for(auto i:IM.second){
//                i->dump();
//            }
//        }
        return;
    };

    void visitCallInst(CallInst &I) {
//        outs()<<"visitCallInst"<<'\n';
//        I.dump();
        auto func = I.getCalledFunction();
        if(!func) {
//            auto related = getPointerOperand(&I)
            return;
        } else{
            StringRef dbgVar = StringRef("llvm.dbg.value");
            if (func ->getName() == dbgVar)
                return;
            set<Value*> funcArgs;
            set<Value*> args;
            if(func->op_begin() == func->op_end()) return;
            for(auto ci = func->op_begin(); ci != func->op_end(); ci++){
                if(ci->get()){
//                    ci->get()->dump();
                    auto related = getValuesFromStack(ci->get());
                    funcArgs.insert(related.begin(), related.end());
                    args.insert(ci->get());
                }
            }
//            set<GlobalVariable*> globalVal;
//            getGlobalsUsedByFunction(*func, globalVal);
//            for(auto g: globalVal){
//                funcArgs.insert(g);
//                args.insert(g);
//            }
            StringRef verAssert = StringRef("__VERIFIER_assert");
//            if (func->getName() == verAssert){
//
//            }
            VMap.insert(make_pair(&I, funcArgs));
            instMap.insert(make_pair(&I, args));
//            outs()<<"visitCallInstOut"<<'\n';
        }




    };

    void visitICmpInst(ICmpInst &I){
//        outs()<<"visitICmpInst"<<'\n';
        set<Value*> ops;
        set<Value*> oriOps;

        for (auto i = I.op_begin(); i != I.op_end(); ++i){
            oriOps.insert(i->get());
            set<Value*> subOps = getValuesFromStack(i->get());

            for (auto op: subOps){
                ops.insert(op);
            }
        }
        VMap.insert(make_pair(&I, ops));
        instMap.insert(make_pair(&I, oriOps));
    };

    void visitBranchInst(BranchInst &I){
//        outs()<<"visitBranchInst"<<'\n';
        if (I.isUnconditional()) return;
        Value* cmpIns = I.getCondition();

        auto subOps = getValuesFromStack(cmpIns);
        VMap.insert(make_pair(&I, subOps));
        instMap.insert(make_pair(&I, set<Value*>({cmpIns})));
    };

    void visitZExtInst(ZExtInst &I){
//        outs()<<"visitZExtInst"<<'\n';
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));

    };

    void visitReturnInst(ReturnInst &I) {

    };

    void visitSwitchInst(SwitchInst &I) {
//        outs()<<"visitSwitchInst"<<'\n';
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
    };

    void visitIndirectBrInst(IndirectBrInst &I) {
//        outs()<<"visitIndirectBrInst"<<'\n';
        auto first = getValuesFromStack(I.getOperand(0));

        VMap.insert(make_pair(&I, first));
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
    };

    void visitFCmpInst(FCmpInst &I) {
//        outs()<<"visitIndirectBrInst"<<'\n';
        unsigned int opNumber = I.getNumOperands();
        set<Value*> ops;
        set<Value*> oriOps;
        for (unsigned int i = 0; i < opNumber; ++i){
            oriOps.insert(I.getOperand(i));
            set<Value*> subOps = getValuesFromStack(I.getOperand(i));
            for (auto op: subOps){
                ops.insert(op);
            }

        }
        VMap.insert(make_pair(&I, ops));
        instMap.insert(make_pair(&I, oriOps));
    };

    void visitAllocaInst(AllocaInst &I){
    };

    void visitLoadInst(LoadInst &I){
//        outs()<<"visitLoadInst"<<'\n';
        Value* loadVar = I.getPointerOperand();
//        if(auto al = dyn_cast<AllocaInst>(loadVar))
//            outs()<<al->getParent()->getName()<<'\n';
        auto it = ptrStack.find(loadVar);
//        if(I.getType()->isPointerTy())
//            loadLink.insert(make_pair(&I, loadVar));
        if (it != ptrStack.end())
        {
//            outs()<<"the Ptr:\n";
//            it->second->dump();
            VMap.insert((make_pair(&I, getValuesFromStack(it->second))));
            instMap.insert(make_pair(&I, set<Value*>({it->second})));
        }
        else {
//            outs()<<"the Ptr:\n";
            auto relatedVars = getValuesFromStack(loadVar);
//            for(auto r: relatedVars){
//                r->dump();
//            }
            VMap.insert(make_pair(&I, relatedVars));
            instMap.insert(make_pair(&I, set<Value*>({loadVar})));
        }

    };
    void visitStoreInst(StoreInst &I){
//        outs()<<"visitStoreInst"<<'\n';
        auto sourceValue = I.getOperand(0);
        auto targetValue = I.getOperand(1);

//        auto iter = ptrStack.find(targetValue);
//        auto VMapIter = VMap.find(targetValue);
//        if(iter != ptrStack.end()) ptrStack.erase(iter);
//        if(VMapIter != VMap.end()) VMap.erase(targetValue);
        ptrStack[targetValue] = sourceValue;
//        VMap
//        Value* infectedPtr;
        auto ptrIter = ptrLink.find(targetValue);
        if (ptrIter != ptrLink.end()){
            infectedPtrSet.insert(ptrIter->second);
        } else
            infectedPtrSet.insert(targetValue);

    };
    void visitGetElementPtrInst(GetElementPtrInst &I) {
//        outs()<<"visitGetElementPtrInst"<<'\n';
        if (I.getNumIndices() <= 1 ){

            //if indices <= 1, it is a pointer
            auto ptrOp = getValuesFromStack(I.getPointerOperand());
            set<Value*> relatedVals;
            relatedVals.insert(ptrOp.begin(), ptrOp.end());
            set<Value*> relatedInst;
            auto indexOp =I.getOperand(1);
            relatedInst.insert(I.getPointerOperand());
            if (!isa<ConstantData>(indexOp)){
                auto relatedIdxOp = getValuesFromStack(indexOp);
                relatedVals.insert(relatedIdxOp.begin(), relatedIdxOp.end());
                relatedInst.insert(indexOp);
            }

            VMap.insert(make_pair(&I, relatedVals));
            instMap.insert(make_pair(&I, relatedInst));
        }else{

            set<Value*> indexes;
            set<Value*> relatedIdx;
            relatedIdx.insert(I.getPointerOperand());
            for(auto indexOp = I.idx_begin(); indexOp != I.idx_end(); ++indexOp){

                if(!isa<ConstantData>(*indexOp)){
//                    if(auto output= dyn_cast<Instruction>((*indexOp))){
//                        (*output).dump();
//                    }
                    indexes.insert(*indexOp);
                    auto theRelated = getValuesFromStack(*indexOp);
                    relatedIdx.insert(theRelated.begin(), theRelated.end());
                }
            }
            if(indexes.size() >0){
                instMap.insert(make_pair(&I, indexes));
                VMap.insert(make_pair(&I, relatedIdx));
            }

        }
        auto iter = ptrLink.find(I.getPointerOperand());
        if (iter != ptrLink.end()){
            ptrLink.insert(make_pair(&I, iter->second));
        } else
            ptrLink.insert(make_pair(&I, I.getPointerOperand()));
    }

    void visitTruncInst(TruncInst &I) {
//        outs()<<"visitTruncInst"<<'\n';
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitSExtInst(SExtInst &I) {
//        outs()<<"visitSExtInst"<<'\n';
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitFPTruncInst(FPTruncInst &I) {
//        outs()<<"visitFPTruncInst"<<'\n';
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitFPExtInst(FPExtInst &I) {
//        outs()<<"visitFPExtInst"<<'\n';
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitUIToFPInst(UIToFPInst &I) {
//        outs()<<"visitUIToFPInst"<<'\n';
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitSIToFPInst(SIToFPInst &I) {
//        outs()<<"visitSIToFPInst"<<'\n';
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitFPToUIInst(FPToUIInst &I) {
//        outs()<<"visitSIToFPInst"<<'\n';
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitFPToSIInst(FPToSIInst &I) {
//        outs()<<"visitFPToSIInst"<<'\n';
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitPtrToIntInst(PtrToIntInst &I) {
//        outs()<<"visitPtrToIntInst"<<'\n';
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitIntToPtrInst(IntToPtrInst &I) {
//        outs()<<"visitIntToPtrInst"<<'\n';
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitBitCastInst(BitCastInst &I) {
        if (I.getOperand(0)->getType()->isPointerTy()){
            auto ptrIter = ptrLink.find(I.getOperand(0));
            if (ptrIter != ptrLink.end()) ptrLink.insert(make_pair(&I, ptrIter->second));
            else
            ptrLink.insert(make_pair(&I, I.getOperand(0)));
        }
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitSelectInst(SelectInst &I) {
//        outs()<<"visitSelectInst"<<'\n';
        set<Value*> relatedVals;
        auto relatedCondition = getValuesFromStack(I.getCondition());
        auto relatedTrueValue = getValuesFromStack(I.getTrueValue());
        auto relatedFalseValue = getValuesFromStack(I.getFalseValue());
        relatedVals.insert(relatedCondition.begin(), relatedCondition.end());
        relatedVals.insert(relatedTrueValue.begin(), relatedTrueValue.end());
        relatedVals.insert(relatedFalseValue.begin(), relatedFalseValue.end());

        VMap.insert(make_pair(&I, relatedVals));
        instMap.insert(make_pair(&I, set<Value*>({I.getCondition(), I.getTrueValue(), I.getFalseValue()})));
    }

//    void visitCallSite(CallSite CS) {
//    }

    void visitInvokeInst(InvokeInst &I) {

    }

    void visitUnreachableInst(UnreachableInst &I) {
    }

    void visitShl(BinaryOperator &I) {
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitLShr(BinaryOperator &I) {
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitAShr(BinaryOperator &I) {
        auto first = getValuesFromStack(I.getOperand(0));
        VMap.insert(make_pair(&I, first));
    }

    void visitVAArgInst(VAArgInst &I) {
        instMap.insert(make_pair(&I, set<Value*>({I.getPointerOperand()})));
        VMap.insert(make_pair(&I, getValuesFromStack(I.getPointerOperand())));
    }

    void visitExtractElementInst(ExtractElementInst &I) {
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(1)})));
        VMap.insert(make_pair(&I, getValuesFromStack(I.getOperand(1))));
    }

    void visitInsertElementInst(InsertElementInst &I) {

    }

    void visitShuffleVectorInst(ShuffleVectorInst &I) {
    }

    void visitExtractValueInst(ExtractValueInst &I) {
        instMap.insert(make_pair(&I, set<Value*>({I.getOperand(0)})));
        VMap.insert(make_pair(&I, getValuesFromStack(I.getOperand(0))));
    }

    void visitInsertValueInst(InsertValueInst &I) {

    }

    void visitInstruction(Instruction &I) {
//        outs()<<"the UnaryInstruction\n";
//        if (isa<UnaryInstruction>(&I)){
//            I.dump();
//        }
    }
};

BasicBlock::iterator getLastInsertionPt(BasicBlock* BB){
    Instruction* FirstNonPHI = BB->getFirstNonPHI();
    if(!FirstNonPHI) return BB->end();
    BasicBlock::iterator InsertPt = BB->back().getIterator();
    BasicBlock::iterator FNPiterator = FirstNonPHI->getIterator();
    while((isa<PHINode>(InsertPt) or InsertPt->isEHPad()) and InsertPt != FNPiterator) {
        --InsertPt;
    }
    return InsertPt;
}

class LoopParser{
    Loop* Lp;
    map<Value*, vector<Value*>> VStack;
    vector<vector<BasicBlock*>> paths;
    set<Value*> iterableVal;
    set<LoadInst*> instrumentLoads;
    set<Value*> outerVals;
    set<Value*> instrumentVals;
    set<Value*> infectedPtrs;
    map<Value*, Value*> ptrLink;
//    bool isOuterVal(Value* val){
//        if(auto I = dyn_cast<Instruction>(val)){
//            if(!targetLoop->contains(I->getParent())){
//                return true;
//            }
//        }
//        return false;
//    }


    SmallPtrSet<BasicBlock*, 8> getConditionBlks(){
        SmallVector<BasicBlock*, 8> EBs;
        Lp->getExitBlocks(EBs);
        SmallPtrSet<BasicBlock*, 8> condBlks;
        if(!EBs.empty()){
            for (auto bb = EBs.begin(); bb != EBs.end(); ++bb){
                auto pre = predecessors((*bb));
                for (BasicBlock* pre_end : pre){
                    if (Lp ->contains(pre_end)){
                        condBlks.insert(pre_end);
                    }
                }
            }
        }
        return condBlks;
    }



    void extractCriticalVal(BasicBlock* blk,  vector<vector<BasicBlock*>> allPaths){
        set<Value*> criticalVals;
//      如果是一条路径，则所有branch都是critical variable
//        outs()<<"the exit block:  "<< blk->getName()<<'\n';
//        outs()<<"the number of paths:" << allPaths.size()<<'\n';
        if (allPaths.size() == 1){
            auto targetPath = *(allPaths.begin());
            Visitor pathVisitor = Visitor(targetPath);
            pathVisitor.link();
            map<Value*, Value*> singleEge;
            for(auto bb:targetPath){
                if(succ_size(bb) > 1){
                    for(auto I = bb->begin(); I != bb->end(); ++I){
                        if(BranchInst* brInst = dyn_cast<BranchInst>(&(*I))){
                            bool isVisit = false;
                            set<LoadInst*> loads;
                            auto linked = pathVisitor.recurseVisit(brInst, isVisit, loads);
                            for(auto val:linked){
                                if (isIterableVals(val)) {
                                    iterableVal.insert(val);
                                }
                            }
                            if (loads.size()>0){
                                for(LoadInst* loadVar : loads){
                                    auto relatedPtrs = pathVisitor.getRelatedValue(loadVar->getPointerOperand());
                                    bool isCritical;
                                    for (auto ptr: relatedPtrs){
                                        if (ptr->getType()->isArrayTy()){
                                            if (auto ptrInst = dyn_cast<Instruction>(ptr)){
                                                if (Lp->contains(ptrInst))
                                                    isCritical = true;
                                            }
                                        } else if (ptr->getType()->isPointerTy()){
                                            if(isIterableVals(ptr))
                                                isCritical = true;
                                        }
                                        if (isCritical) instrumentLoads.insert(loadVar);

                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else{
            //   如果是多条路径，则需要逐个block依次遍历
            auto header = Lp->getHeader();
            endToUp(blk, header, allPaths, instrumentLoads, criticalVals);
        }
        for (auto val : criticalVals){
            if (isIterableVals(val)){
                iterableVal.insert(val);
            } else if(isOuterValue(val)){
                outerVals.insert(val);
            }
        }
//        instrumentLoads.insert(relatedLoads.begin(), relatedLoads.end());
    }
    set<BasicBlock*> isDiamond(vector<BasicBlock*> blks){
        set<BasicBlock*> r;
        SmallPtrSet<BasicBlock*, 8> hash;
        for(auto &bb:blks){
            if (hash.count(bb)){
                r.insert(bb);
            } else{
                hash.insert(bb);
            }
        }

        return r;
    }
    bool isOuterValue(Value* val){
        if(auto inst = dyn_cast<Instruction>(val)){
            BasicBlock* fatherBB = (*inst).getParent();
            if (!Lp->contains(fatherBB)) return true;
        }
        return false;
    }
    void addInfectedPtr(vector<BasicBlock*> thePath){
        Visitor pv = Visitor(thePath);
        pv.link();
        infectedPtrs.insert(pv.infectedPtrSet.begin(), pv.infectedPtrSet.end());
        ptrLink.insert(pv.ptrLink.begin(), pv.ptrLink.end());

    }
    bool isChangedLoad(LoadInst* ld){
        bool isChanged = false;
        auto relatedPtr = ld->getPointerOperand();

//        outs()<<"the ptrLink:\n";
//        for (auto it: ptrLink){
//            outs()<<"key:\n";
//            it.first->dump();
//            outs()<<"value:\n";
//            it.second->dump();
//        }
//        outs()<<"the changed ptr:\n";
//        for (auto it:infectedPtrs){
//            it->dump();
//        }
        if(infectedPtrs.count(relatedPtr))
            isChanged = true;
        else{
            auto ptrIter = ptrLink.find(relatedPtr);
            if(ptrIter != ptrLink.end()){
                if(infectedPtrs.count(ptrIter->second))
                    isChanged = true;
            }
        }

        return isChanged;
    }
    set<LoadInst*> trimLoad(set<LoadInst*> &loads){
        set<LoadInst*> trimed;
        for(auto ld: loads){
            if(isChangedLoad(ld))
                trimed.insert(ld);
        }
//        outs()<<"can get here4?\n";
        return trimed;
    }
    void endToUp(BasicBlock* endBlk, BasicBlock* topBlk, vector<vector<BasicBlock*>> allPaths, set<LoadInst*> &criticalLoads, set<Value*> &criVals, bool isFunc = false) {
        set<BasicBlock *> allBBInPath;
        for (auto p: allPaths) {
            for (auto bb: p) {
                allBBInPath.insert(bb);
            }
        }
        SmallPtrSet < BasicBlock * , 8 > singlePath;

        stack < BasicBlock * > BBStack;
        stack <vector<BasicBlock *>> pathStack;
        stack<set<Value*>> criticalStack;
        set<Value*> curCritVal;
        curCritVal.insert(criVals.begin(), criVals.end());
        criticalStack.push(curCritVal);
        BBStack.push(endBlk);
        pathStack.push(vector < BasicBlock * > {endBlk});
        map < BasicBlock * , BasicBlock * > twoPredMap;
        set<BasicBlock*> infectedBlk;
        infectedBlk.insert(endBlk);
        set<LoadInst*> tmpLoad;
//        map<BasicBlock*, set<Value*>> blkToValMap;


        while (!BBStack.empty()) {
            BasicBlock *curBB = BBStack.top();

            vector<BasicBlock*> curPath = pathStack.top();
            set<Value*> curCriticalVal = criticalStack.top();
            BBStack.pop();
            pathStack.pop();
            criticalStack.pop();
//            if (curBB->getName() == "while.body"){
//                for(auto I: infectedBlk){
//                    outs()<<I->getName()<<'\n';
//                }
//            }

            if (pred_empty(curBB) or curBB == topBlk) {

                if (curBB == topBlk){
                    Visitor topVisitor = Visitor(vector<BasicBlock*>({curBB}));
                    topVisitor.link();

                    bool isVisited = false;
                    set<Value*> nextCritiVals;
//                    BranchInst* brInst;
                    for (auto i = curBB->begin(); i != curBB->end(); ++i) {
                        if(auto brI = dyn_cast<BranchInst>(&(*i))){
                            curCriticalVal.insert(brI);
                        }
                    }

//                    outs()<<"the curCritical Value:\n";
                    for(auto cri: curCriticalVal){
                        auto relateds = topVisitor.recurseVisit(cri, isVisited, tmpLoad);
                        nextCritiVals.insert(relateds.begin(), relateds.end());
                    }

//                    outs()<<"The instMap:\n";
//                    auto instMap = topVisitor.getInstMap();
//                    for(auto &m:instMap){
//                        outs()<<"key:\n";
//                        m.first->dump();
//                        outs()<<"value:\n";
//                        for(auto v: m.second){
//                            v->dump();
//                        }
//                    }
                    for(auto v: nextCritiVals){
                        if (isIterableVals(v) or isOuterValue(v)){
                            criVals.insert(v);
                        }
                    }
//                    outs()<<"all the load instructions!\n";
//                    for (auto ins: tmpLoad){
//                        ins->dump();
//                    }
                    addInfectedPtr(curPath);
                    auto trimed = trimLoad(tmpLoad);

                    criticalLoads.insert(trimed.begin(), trimed.end());

 //                    criVals.insert(nextCritiVal.begin(), nextCritiVal.end());
                }

            } else {
                if (isFunc or Lp->contains(curBB)){
//                    outs()<<"The current BB: " << curBB->getName() << '\n';
                    bool isInfectedBB = false;
                    if (succ_size(curBB) > 1) {
                        vector<BasicBlock*> diamonds;
//                        outs()<<"checkPoint 1!\n";
                        for (auto succBB = succ_begin(curBB); succBB != succ_end(curBB); ++succBB) {
                            if ((not allBBInPath.count(*succBB)) and allBBInPath.size() > 0) {
//                                outs()<<"infected here 1!\n";
                                isInfectedBB = true;
                            }
                            if (pred_size(*succBB) == 1){
                                if (infectedBlk.count(*succBB)){
//                                    outs()<<"infected here 2!\n";
                                    isInfectedBB = true;
                                }
                            }
                            diamonds.push_back(*succBB);
                            auto predIter = twoPredMap.find(*succBB);
                            if (predIter != twoPredMap.end())
                                diamonds.push_back(predIter->second);
                        }
//                        outs()<<"the diamonds block:\n";
//                        for (auto DD: diamonds){
//                            outs()<<DD->getName()<<'\n';
//                        }
                        set<BasicBlock*> diamondsBlk = isDiamond(diamonds);
                        if(!diamondsBlk.empty()){

                            auto targetDiamond = *diamondsBlk.begin();
//                            auto iter = std::find(diamonds.begin(), diamonds.end(), targetDiamond);
//                            diamonds.erase(iter);
                            for(auto &d:diamonds){
                                if(d != targetDiamond)
                                    twoPredMap.erase(d);
                            }
                            auto twoPredIter = twoPredMap.find(targetDiamond);
                            if (twoPredIter != twoPredMap.end())
                                twoPredMap.insert(make_pair(curBB, twoPredIter->second));
                            if (infectedBlk.count(targetDiamond))
                                infectedBlk.insert(curBB);
                        }
                        if (isInfectedBB) {
                            infectedBlk.insert(curBB);
//                       如果被影响了就抽出branch变量
//                            BranchInst* curBranch;
                            for (auto i = curBB->begin(); i != curBB->end(); ++i) {
                                if (BranchInst* brInst = dyn_cast<BranchInst>(&(*i))){
//                                    outs()<<"the targetBlk is:"<<curBB->getName()<<'\n';
//                                    outs()<<"the corresponding branchInst is:"<<'\n';
//                                    brInst->dump();
                                    curCriticalVal.insert(brInst);
                                }

                            }
                        }

                    } else{
//                        outs()<<"checkPoint 2!\n";
                        auto singleSucc = curBB->getSingleSuccessor();
                        if (singleSucc){
                            if (infectedBlk.count(singleSucc) and pred_size(singleSucc) == 1){
                                infectedBlk.insert(curBB);
                            }
                            if (pred_size(singleSucc) > 1)
                                twoPredMap.insert(make_pair(curBB, singleSucc));
                            else{
                                auto twoPredIter = twoPredMap.find(singleSucc);
                                if (twoPredIter != twoPredMap.end())
                                    twoPredMap.insert(make_pair(curBB, twoPredIter->second));
                            }
                        }

                    }
//                    outs()<<"checkPoint 3!\n";
                }
                bool isInfectedBB = false;
//                outs()<<"current BasicBlock:"<<curBB->getName()<<'\n';
//                outs()<<"the critical values:\n";
//                if(curCriticalVal.empty())
//                    outs()<<"No critical Values!\n";
                for (auto predPtr = pred_begin(curBB); predPtr != pred_end(curBB); ++predPtr) {
                    BasicBlock* pred = *predPtr;
                    if (std::find(curPath.begin(), curPath.end(), pred) == curPath.end()) {
                        set<Value*> nextCritiVal;
//                        outs()<<"can get here1?\n";
                        auto visitCurBB = Visitor(vector<BasicBlock *>({curBB}), pred);
//                        outs()<<"can get here2?\n";
                        visitCurBB.link();
//                        outs()<<"can get here3?\n";
                        for (auto criticalIter = curCriticalVal.begin(); criticalIter != curCriticalVal.end(); ++criticalIter){
                            auto crit = *criticalIter;
                            set<Value*> results = visitCurBB.recurseVisit(crit, isInfectedBB, tmpLoad);
//                                crit->dump();
//                                outs()<<"the instrument vals:\n";
//                                for(auto &theInst: results){
//                                    theInst->dump();
//                                }
                            nextCritiVal.insert(results.begin(), results.end());
                        }
//                        outs()<<"can get here4?\n";
                        vector < BasicBlock * > newPath = curPath;
                        newPath.push_back(pred);
                        BBStack.push(pred);
                        pathStack.push(newPath);
                        criticalStack.push(nextCritiVal);
                    }
                }
//                outs()<<"checkPoint 4!\n";
                if (isInfectedBB)
                    infectedBlk.insert(curBB);

            }

        }
    }

    vector<vector<BasicBlock*>> pathExtraction(BasicBlock* targetBlk){
        vector<vector<BasicBlock*>> allPaths;
        BasicBlock* tail = getTail();
        assert(tail != nullptr);
        BasicBlock* header = Lp -> getHeader();
        stack<BasicBlock*> BBStack;
        stack<vector<BasicBlock*>> pathStack;
        BBStack.push(header);
        pathStack.push(vector<BasicBlock*> {header});
        while(!BBStack.empty()){
            BasicBlock* CurBB =  BBStack.top();
            vector<BasicBlock*> curPath = pathStack.top();
            BBStack.pop();
            pathStack.pop();
            if (succ_empty(CurBB) or CurBB == targetBlk or CurBB == tail){
                if (CurBB == targetBlk){
                    allPaths.push_back(curPath);
                }
            } else{
                for (succ_iterator succPtr = succ_begin(CurBB); succPtr != succ_end(CurBB); ++succPtr){
                    BasicBlock* sucBB = *succPtr;
                    if (std::find(curPath.begin(), curPath.end(), sucBB) == curPath.end()){
                        vector<BasicBlock *> newPath = curPath;

                        newPath.push_back(sucBB);
                        BBStack.push(sucBB);
                        pathStack.push(newPath);
                    }
                }

            }
        }
        return allPaths;
    }
//    void getSinglePath(SmallPtrSet<BasicBlock*, 8> condition_blks){
//        for (auto blk = condition_blks.begin(); blk != condition_blks.end(); ++blk){
//            for (auto p : paths){
//
//            }
//        }
//    }
//    set<Value*> getIterableVals(){
//        BasicBlock* header = Lp->getHeader();
//        BasicBlock* tail = getTail();
//        set<Value*> iterableVals;
//        for (auto V = header->begin(); V != header->end(); ++V){
//            if (PHINode* iterVal = dyn_cast<PHINode>(V)){
//                bool isOutside = false;
//                bool isTail = false;
//                if (iterVal->getParent() == header){
//                    for(auto begin = iterVal->block_begin(); begin!= iterVal->block_end(); begin++){
//                        if(!Lp->contains((*begin)))
//                            isOutside = true;
//                        if((*begin) == tail)
//                            isTail = true;
//                    }
//                    if(isOutside&&isTail)
//                        iterableVals.insert(iterVal);
//                }
//            }
//        }
//
//        return iterableVals;
//    }
    bool isIterableVals(Value* V){
        auto tailBB = getTail();
        auto header = Lp->getHeader();
        if (PHINode* iterVal = dyn_cast<PHINode>(V)){
            bool isOutside = false;
            bool isTail = false;
            if (iterVal->getParent() == header){
                for(auto begin = iterVal->block_begin(); begin!= iterVal->block_end(); begin++){
                    if(!Lp->contains((*begin)))
                        isOutside = true;
                    if((*begin) == tailBB)
                        isTail = true;
                }
                if(isOutside&&isTail)
                    return true;
            }
        }
        return false;
    }

    set<Value*> getLatchVal(set<Value*> valSet){
        BasicBlock* tail = getTail();
        set<Value*> latchValue;
        for(auto &v:valSet){
            if (auto interVal = dyn_cast<PHINode>(v)){
                latchValue.insert(interVal->getIncomingValueForBlock(tail));
            }
        }
        return latchValue;
    }

    void valLink(){
        SmallVector<BasicBlock*, 8> EBs;
        BasicBlock* tail = getTail();
//        auto theIterVal = getIteratableVals();
        BasicBlock* header = Lp->getHeader();
        Lp->getExitBlocks(EBs);
        set<BasicBlock*> exitBBs;
        exitBBs.insert(EBs.begin(), EBs.end());
        for (auto &exitBlk: exitBBs){
            auto targetPaths = pathExtraction(exitBlk);
            extractCriticalVal(exitBlk, targetPaths);
        }

//        outs()<<"The Instrument Number:"<<iterableVal.size()<<'\n';

        set<Value*> latchValue = getLatchVal(iterableVal);
//        for (auto l: latchValue){
//            l->dump();
//        }
        endToUp(tail, header, {}, instrumentLoads, latchValue, true);
        for(auto &val : latchValue){
            if (isIterableVals(val)){
                iterableVal.insert(val);
            } else if(isOuterValue(val)){
                outerVals.insert(val);
            }
        }
        auto theFinalLatch = getLatchVal(iterableVal);
        instrumentVals.insert(theFinalLatch.begin(), theFinalLatch.end());
        instrumentVals.insert(outerVals.begin(), outerVals.end());
    }

public:
//    map<Value*, vector<Value*>> GEPMap;
    LoopParser(Loop* L):Lp(L){
        paths = pathExtraction(getTail());
        valLink();
    }
    set<Value*> getInstrumentValues(){
        return instrumentVals;
    }
    set<LoadInst*> getLoadValues(){
        return instrumentLoads;
    }
    BasicBlock* getTail(){

        return Lp->getLoopLatch();
    }

    SmallPtrSet<BasicBlock*, 8> getCondBlks(){
        return getConditionBlks();
    }
    vector<vector<BasicBlock*>> loopPath(){
        return paths;
    }

};
/**  VoidTyID = 0,    ///<  0: type with no size
    HalfTyID,        ///<  1: 16-bit floating point type
    FloatTyID,       ///<  2: 32-bit floating point type
    DoubleTyID,      ///<  3: 64-bit floating point type
    X86_FP80TyID,    ///<  4: 80-bit floating point type (X87)
    FP128TyID,       ///<  5: 128-bit floating point type (112-bit mantissa)
    PPC_FP128TyID,   ///<  6: 128-bit floating point type (two 64-bits, PowerPC)
    LabelTyID,       ///<  7: Labels
    MetadataTyID,    ///<  8: Metadata
    X86_MMXTyID,     ///<  9: MMX vectors (64 bits, X86 specific)
    TokenTyID,       ///< 10: Tokens

    // Derived types... see DerivedTypes.h file.
    // Make sure FirstDerivedTyID stays up to date!
    IntegerTyID,     ///< 11: Arbitrary bit width integers
    FunctionTyID,    ///< 12: Functions
    StructTyID,      ///< 13: Structures
    ArrayTyID,       ///< 14: Arrays
    PointerTyID,     ///< 15: Pointers
    VectorTyID       ///< 16: SIMD 'packed' format, or other vector type
 **/

Function* getRequiredHash(Value* val, vector<Function*> hashFuncs){
    Type* valType = val->getType();
    switch (valType->getTypeID()) {
        case Type::FloatTyID:
            return hashFuncs[0];
        case Type::DoubleTyID:
            return hashFuncs[1];
        case Type::X86_FP80TyID:
            return hashFuncs[2];
        case Type::IntegerTyID:{
            auto bitSize = valType->getScalarSizeInBits();
            switch (bitSize) {
                case 1:
                    return hashFuncs[3];
                case 8:
                    return hashFuncs[4];
                case 16:
                    return hashFuncs[5];
                case 32:
                    return hashFuncs[6];
                case 64:
                    return hashFuncs[7];
                default:
                    break;
            }
        }
//
//        case Type::PointerTyID:
//            return hashFuncs[8];
        default:
            return nullptr;
    }
}
void getSubLoop(Loop* L, set<Loop*> &S){
    auto subLoops = L->getSubLoops();
    if (subLoops.size() != 0){
        S.insert(subLoops.begin(), subLoops.end());
        for (auto sub = subLoops.begin(); sub != subLoops.end(); sub++){
            getSubLoop(*sub, S);
        }
    }

}
static int notInstrumentedLoops = 0; //There are some loops did not be instrumented successfully.
static int allFoundLoops = 0; // Successfully instrumented loops.

bool LoopInstrument::runOnFunction (Function &F) {
    outs()<<F.getName()<<'\n';
    unsigned long recordNum = 1000;
    Module* M = F.getParent();
    LLVMContext &C = M->getContext();
    IntegerType *Int1Ty = IntegerType::getInt1Ty(C);
    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    PointerType *Int8PtrTy = PointerType::getInt8PtrTy(C);
    PointerType *Int8PtrPtrTy = PointerType::get(Int8PtrTy, 0);
    IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
//    PointerType *Int8PtrTy = PointerType::getInt8PtrTy(C);
    PointerType *Int64PtrTy = PointerType::getInt64PtrTy(C);
    PointerType *Int32PtrTy = PointerType::getInt32PtrTy(C);
    Type* VoidTy = Type::getVoidTy(C);
//    Type* VoidPtrTy = PointerType::getVoidTy(C);

    static Function* floatHash = Function::Create(FunctionType::get(Int64Ty, ArrayRef<Type*>({Int8Ty}), true), GlobalValue::ExternalLinkage, "floatHash", M);
    static Function* doubleHash = Function::Create(FunctionType::get(Int64Ty, ArrayRef<Type*>({Int32Ty}), true), GlobalValue::ExternalLinkage, "doubleHash", M);
    static Function* longDoubleHash = Function::Create(FunctionType::get(Int64Ty, ArrayRef<Type*>({Int64Ty}), true), GlobalValue::ExternalLinkage, "longDoubleHash", M);
    static Function* boolHash = Function::Create(FunctionType::get(Int64Ty, ArrayRef<Type*>({Int1Ty}), true), GlobalValue::ExternalLinkage, "boolHash", M);
    static Function* charHash = Function::Create(FunctionType::get(Int64Ty, ArrayRef<Type*>({Int8Ty}), true), GlobalValue::ExternalLinkage, "charHash", M);
    static Function* i16Hash = Function::Create(FunctionType::get(Int64Ty, ArrayRef<Type*>({Int16Ty}), true), GlobalValue::ExternalLinkage, "i16Hash", M);
    static Function* i32Hash = Function::Create(FunctionType::get(Int64Ty, ArrayRef<Type*>({Int32Ty}), true), GlobalValue::ExternalLinkage, "i32Hash", M);
    static Function* i64Hash = Function::Create(FunctionType::get(Int64Ty, ArrayRef<Type*>({Int64Ty}), true), GlobalValue::ExternalLinkage, "i64Hash", M);
//    static Function* anyTyFunc = Function::Create(FunctionType::get(Int64Ty, ArrayRef<Type*>({Int8PtrTy, Int32PtrTy}), true), GlobalValue::ExternalLinkage, "anyTypeHash", M);
//    static Function* ptrHash = Function::Create(FunctionType::get(Int64Ty, ArrayRef<Type*>({Int64Ty}), true), GlobalValue::ExternalLinkage, "ptrHash", M);
    static Function* hashCombineFunc = Function::Create(FunctionType::get(Int8PtrTy, ArrayRef<Type*>({Int64PtrTy, Int32Ty}), true), GlobalValue::ExternalLinkage, "hashCombine", M);
    static Function* checkFunc = Function::Create(FunctionType::get(VoidTy, ArrayRef<Type*>({Int8PtrPtrTy, Int8PtrTy, Int32PtrTy, Int32PtrTy}), true), GlobalValue::ExternalLinkage, "_check", M);
    static Function* freeFunc = Function::Create(FunctionType::get(VoidTy, ArrayRef<Type*>({Int8PtrPtrTy, Int32PtrTy}), true), GlobalValue::ExternalLinkage, "checkpoint_free", M);

//    PointerType *CharPtrTy = PointerType::getUnqual(Int8Ty);


    auto entryBB = &F.getEntryBlock();
    auto entryIP = getLastInsertionPt(entryBB);
    IRBuilder<> entryIRB(&(*entryIP));

//    auto labelArray = entryIRB.CreateAlloca(arrayType);
    LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
    unsigned int loopNum = 0;
    set<Loop*> allLoops;
    for(LoopInfo::iterator LIT = LI.begin(), LEND = LI.end(); LIT != LEND; ++LIT){
        allLoops.insert(*LIT);
        getSubLoop(*LIT, allLoops);
    }

    auto DT = M->getDataLayout();
    int realNum = 0;
    for(auto LIT = allLoops.begin(), LEND = allLoops.end(); LIT != LEND; ++LIT){
        realNum++;
//    for(auto LIT = LI.begin(), LEND = LI.end(); LIT != LEND; ++LIT){
        //parse loop
        allFoundLoops++;
        Loop* targetLoop = *LIT;
        auto preHeader = targetLoop->getLoopPreheader();

        ///如果没有正常的preHeader,那就直接略过了
        if(!preHeader){
//            notInstrumentedLoops++;
//            outs()<<"no pre-header!\n";
//            continue;
            preHeader = entryBB;
        }
        auto loopTail = targetLoop->getLoopLatch();
        ///同样的，如果没有latch,也略过
        if(!loopTail){
            notInstrumentedLoops++;
            outs()<<"no tail!\n";
            continue;
        }
        ///header处建立builder
        BasicBlock* header = targetLoop->getHeader();
        BasicBlock::iterator headerIP = getLastInsertionPt(header);
        IRBuilder<> headerBuilder(&(*headerIP));
        ///loop的exitBlk，如果没有，则说明该loop为infinite loop
        SmallVector<BasicBlock*, 8> exitBBs;
        targetLoop->getExitBlocks(exitBBs);
        if (exitBBs.empty()){
            notInstrumentedLoops++;
            outs()<<"Find a infinite Loop!\n";
            static Function* crash = Function::Create(FunctionType::get(VoidTy , false), GlobalValue::ExternalLinkage, "_crash", M);
            headerBuilder.CreateCall(crash)->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));
            continue;
        }

//        return true;
        LoopParser lp(targetLoop);
//        continue;
        auto instrumentVals = lp.getInstrumentValues();
        auto loadVals = lp.getLoadValues();
        instrumentVals.insert(loadVals.begin(), loadVals.end());
//        outs()<<targetLoop->getName()<<'\n';
        loopNum++;
        ///插桩变量的数量
        int condValNum = instrumentVals.size();
        auto recordArrayTy = ArrayType::get(Int8PtrTy, recordNum);
        string recordArrayName = "_recordArray" + to_string(loopNum);

        ///在preHeader处建立Builder
        BasicBlock::iterator preHeaderIP = getLastInsertionPt(preHeader);
        IRBuilder<> preHeaderBuilder(&(*preHeaderIP));
        ///preHeader插入record数组，记录所有label的信息
        auto recordArray = entryIRB.CreateAlloca(recordArrayTy,nullptr, recordArrayName);

        ///tail处建立builder
        BasicBlock::iterator tailIP = getLastInsertionPt(loopTail);
        IRBuilder<> tailBuilder(&(*tailIP));


//        for(auto instVal: instrumentVals){
//            instVal->dump();
//        }
//        vector<Value*> arrayVec;
//    DataLayout DT(M);

        ///在preHeader 插入counter，初值赋0
        string counterName = "_counter" + to_string(loopNum);
        auto counter = preHeaderBuilder.CreateAlloca(Int32Ty, nullptr, counterName);
        preHeaderBuilder.CreateStore(ConstantInt::get(Int32Ty, 0), counter)->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));

        ///有多少个instrumentVals，就插入多少个label，用来记录每次循环的各种关键变量信息

        ArrayType* arrayType = ArrayType::get(Int64Ty, condValNum);
        string labelNames = "_label"+ to_string(loopNum);
        auto labelArray = preHeaderBuilder.CreateAlloca(arrayType, nullptr, labelNames);

        ///instrumentNum 用来记录totalArray的元素数量
        auto instrumentNum = entryIRB.CreateAlloca(Int32Ty);
        entryIRB.CreateStore(ConstantInt::get(Int32Ty, 0), instrumentNum)->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));
        if (!instrumentVals.empty()){
            outs()<<"all Instruments:\n";
            int i = 0;
            for(auto instVal: instrumentVals){
//                instVal->dump();
                Value* targetValue;
                if(auto ld = dyn_cast<LoadInst>(instVal)){
                    if(loadVals.count(ld)){
                        auto valType = ld->getType();
                        auto loadLabel = preHeaderBuilder.CreateAlloca(valType, nullptr);
                        auto parentBB = ld->getParent();
                        BasicBlock::iterator parentIP = getLastInsertionPt(parentBB);
                        IRBuilder<> parentIRB(&(*parentIP));
                        parentIRB.CreateStore(ld, loadLabel)->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));
                        targetValue = tailBuilder.CreateLoad(loadLabel->getType()->getPointerElementType(), loadLabel);
                    }
                    else
                        targetValue = instVal;
                } else
                    targetValue = instVal;

                Value* getHash;
                if (targetValue->getType()->getTypeID() == Type::PointerTyID){
                    auto para = tailBuilder.CreatePtrToInt(targetValue, tailBuilder.getInt64Ty());
                    getHash = tailBuilder.CreateZExt(para, tailBuilder.getInt64Ty());
                } else{
                    auto func = getRequiredHash(targetValue, {floatHash, doubleHash, longDoubleHash, boolHash, charHash, i16Hash, i32Hash, i64Hash});
//                    if(!func){
//
//                        auto typeSize = DT.getTypeAllocSize(targetValue->getType());
//                        func = anyTyFunc;
//                        auto theBitCast = tailBuilder.CreateBit
//                    }
                    if(!func){
                        errs()<<"Unknown variable type, the Loop would be jumped\n";
                        return 1;
                    }
                    getHash = tailBuilder.CreateCall(func, ArrayRef<Value*>({targetValue}));
                }
//                    parameter = instVal;


//                }
//                outs()<<"the target parameter:\n";
//                parameter->dump();
//                outs()<<"the function:\n";
//                func->dump();
//                auto getHash = tailBuilder.CreateCall(func, ArrayRef<Value*>({parameter}));
                auto ind = ConstantInt::get(Int32Ty, i);
                auto ptr = tailBuilder.CreateGEP(labelArray->getType()->getPointerElementType(), labelArray, {ConstantInt::get(Int32Ty, 0), ind});
                tailBuilder.CreateStore(getHash, ptr);
                //每次迭代在loopTail中增加1
//                auto inc = tailBuilder.CreateLoad(counter);
//                inc->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));
//                Value* incedCounter = tailBuilder.CreateAdd(inc, ConstantInt::get(Int32Ty, 1));
//                tailBuilder.CreateStore(incedCounter, counter)->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));
                ++i;

                }
            //调用hashCombine
            auto labelArrPtr = tailBuilder.CreateGEP(labelArray->getType()->getPointerElementType(), labelArray, {ConstantInt::get(Int32Ty, 0), ConstantInt::get(Int32Ty, 0)});

            auto newVal = tailBuilder.CreateCall(hashCombineFunc, ArrayRef<Value*>({labelArrPtr, ConstantInt::get(Int32Ty, condValNum)}));

            // call check(unsigned long* oldArr, unsigned long newVal, unsigned int times, unsigned int* instrumentNum)
            //调用record Array
            auto oldArrPtr = tailBuilder.CreateGEP(recordArray->getType()->getPointerElementType(), recordArray, {ConstantInt::get(Int32Ty, 0), ConstantInt::get(Int32Ty, 0)});

//            auto times = tailBuilder.CreateLoad(counter);
//            times->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));
            tailBuilder.CreateCall(checkFunc, ArrayRef<Value*>({oldArrPtr, newVal, counter, instrumentNum}))->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));
            ///在每个loop终止节点处插入free函数，把hash值free掉
            for(auto &exitBlock:exitBBs){
                BasicBlock::iterator exitIP = getLastInsertionPt(exitBlock);
                IRBuilder<> exitBuilder(&(*exitIP));
                auto oldArrPtr_free = exitBuilder.CreateGEP(recordArray->getType()->getPointerElementType(), recordArray, {ConstantInt::get(Int32Ty, 0), ConstantInt::get(Int32Ty, 0)});
                exitBuilder.CreateCall(freeFunc, ArrayRef<Value*>({oldArrPtr_free, instrumentNum}))->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));
            }
            } else{
            outs()<<"Did not find any instruments! An infinite Loop occur!\n";
//            outs()<<"The loop is:\n";
//            outs()<<targetLoop->getName();
            static Function* crash = Function::Create(FunctionType::get(VoidTy , false), GlobalValue::ExternalLinkage, "_crash", M);
            headerBuilder.CreateCall(crash)->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));

        }
        }
        if(allLoops.size()>0){
        string Str;
        raw_string_ostream OS(Str);
        F.print(OS, nullptr);
        ofstream outfile;
        outfile.open("/home/zy/Documents/workplace/fuzzing_for_loop/ToFuzz/tool/AFL-LOOP/llvm-info/" + F.getName().str() + "_out.ll");
        outfile << Str;
        outfile.close();
    }
//
    outs()<<"the loop Number:" <<loopNum<<'\n';
        outs()<<"the real loop Number:" << realNum<<'\n';
    return true;

}

/*---------------------------------------------------*/


static void loopInstrumentPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {


    PM.add(new LoopInstrument());

}


static RegisterStandardPasses LoopInstrumentPass(
        PassManagerBuilder::EP_ModuleOptimizerEarly, loopInstrumentPass);

static RegisterStandardPasses LoopInstrumentPass0(
        PassManagerBuilder::EP_EnabledOnOptLevel0, loopInstrumentPass);




static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {


    PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
        PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
        PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
/*---------------------------------------------------*/
