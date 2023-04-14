; ModuleID = '/home/zy/Documents/workplace/benchmarks/TermComp-infinite/C/AProVE_memory_alloca/svcomp_BradleyMannaSipma-2005CAV-Fig1-modified_false-termination.c'
source_filename = "/home/zy/Documents/workplace/benchmarks/TermComp-infinite/C/AProVE_memory_alloca/svcomp_BradleyMannaSipma-2005CAV-Fig1-modified_false-termination.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @gcd(i32* %y1, i32* %y2) #0 {
entry:
  %y1.addr = alloca i32*, align 8
  %y2.addr = alloca i32*, align 8
  store i32* %y1, i32** %y1.addr, align 8
  store i32* %y2, i32** %y2.addr, align 8
  br label %while.cond

while.cond:                                       ; preds = %if.end, %entry
  %0 = load i32*, i32** %y1.addr, align 8
  %1 = load i32, i32* %0, align 4
  %2 = load i32*, i32** %y2.addr, align 8
  %3 = load i32, i32* %2, align 4
  %cmp = icmp ne i32 %1, %3
  br i1 %cmp, label %while.body, label %while.end

while.body:                                       ; preds = %while.cond
  %4 = load i32*, i32** %y1.addr, align 8
  %5 = load i32, i32* %4, align 4
  %6 = load i32*, i32** %y2.addr, align 8
  %7 = load i32, i32* %6, align 4
  %cmp1 = icmp sgt i32 %5, %7
  br i1 %cmp1, label %if.then, label %if.else

if.then:                                          ; preds = %while.body
  %8 = load i32*, i32** %y1.addr, align 8
  %9 = load i32, i32* %8, align 4
  %10 = load i32*, i32** %y2.addr, align 8
  %11 = load i32, i32* %10, align 4
  %sub = sub nsw i32 %9, %11
  %12 = load i32*, i32** %y1.addr, align 8
  store i32 %sub, i32* %12, align 4
  br label %if.end

if.else:                                          ; preds = %while.body
  %13 = load i32*, i32** %y2.addr, align 8
  %14 = load i32, i32* %13, align 4
  %15 = load i32*, i32** %y1.addr, align 8
  %16 = load i32, i32* %15, align 4
  %sub2 = sub nsw i32 %14, %16
  %17 = load i32*, i32** %y2.addr, align 8
  store i32 %sub2, i32* %17, align 4
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  br label %while.cond

while.end:                                        ; preds = %while.cond
  %18 = load i32*, i32** %y1.addr, align 8
  %19 = load i32, i32* %18, align 4
  ret i32 %19
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
entry:
  %retval = alloca i32, align 4
  %y1 = alloca i32*, align 8
  %y2 = alloca i32*, align 8
  store i32 0, i32* %retval, align 4
  %0 = alloca i8, i64 4, align 16
  %1 = bitcast i8* %0 to i32*
  store i32* %1, i32** %y1, align 8
  %2 = alloca i8, i64 4, align 16
  %3 = bitcast i8* %2 to i32*
  store i32* %3, i32** %y2, align 8
  %call = call i32 @__VERIFIER_nondet_int()
  %4 = load i32*, i32** %y1, align 8
  store i32 %call, i32* %4, align 4
  %call1 = call i32 @__VERIFIER_nondet_int()
  %5 = load i32*, i32** %y2, align 8
  store i32 %call1, i32* %5, align 4
  %6 = load i32*, i32** %y1, align 8
  %7 = load i32, i32* %6, align 4
  %cmp = icmp sge i32 %7, 0
  br i1 %cmp, label %land.lhs.true, label %if.end

land.lhs.true:                                    ; preds = %entry
  %8 = load i32*, i32** %y2, align 8
  %9 = load i32, i32* %8, align 4
  %cmp2 = icmp sge i32 %9, 0
  br i1 %cmp2, label %if.then, label %if.end

if.then:                                          ; preds = %land.lhs.true
  %10 = load i32*, i32** %y1, align 8
  %11 = load i32*, i32** %y2, align 8
  %call3 = call i32 @gcd(i32* %10, i32* %11)
  br label %if.end

if.end:                                           ; preds = %if.then, %land.lhs.true, %entry
  ret i32 0
}

declare dso_local i32 @__VERIFIER_nondet_int() #1

attributes #0 = { noinline nounwind optnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 10.0.1 "}
