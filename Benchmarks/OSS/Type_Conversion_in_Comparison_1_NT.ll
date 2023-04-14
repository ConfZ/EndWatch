; ModuleID = 'Type_Conversion_in_Comparison_1_NT.c'
source_filename = "Type_Conversion_in_Comparison_1_NT.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca i16, align 2
  %3 = alloca i16, align 2
  %4 = alloca i16, align 2
  store i32 0, i32* %1, align 4
  %5 = call i32 (...) @__VERIFIER_nondet_ushort()
  %6 = trunc i32 %5 to i16
  store i16 %6, i16* %3, align 2
  %7 = call i32 (...) @__VERIFIER_nondet_ushort()
  %8 = trunc i32 %7 to i16
  store i16 %8, i16* %4, align 2
  %9 = load i16, i16* %3, align 2
  store i16 %9, i16* %2, align 2
  br label %10

10:                                               ; preds = %28, %0
  %11 = load i16, i16* %2, align 2
  %12 = zext i16 %11 to i32
  %13 = load i16, i16* %3, align 2
  %14 = zext i16 %13 to i32
  %15 = load i16, i16* %4, align 2
  %16 = zext i16 %15 to i32
  %17 = add nsw i32 %14, %16
  %18 = icmp slt i32 %12, %17
  br i1 %18, label %19, label %31

19:                                               ; preds = %10
  %20 = load i16, i16* %3, align 2
  %21 = zext i16 %20 to i32
  %22 = load i16, i16* %4, align 2
  %23 = zext i16 %22 to i32
  %24 = add nsw i32 %21, %23
  %25 = icmp sgt i32 %24, 65535
  br i1 %25, label %26, label %27

26:                                               ; preds = %19
  call void @abort() #3
  unreachable

27:                                               ; preds = %19
  br label %28

28:                                               ; preds = %27
  %29 = load i16, i16* %2, align 2
  %30 = add i16 %29, 1
  store i16 %30, i16* %2, align 2
  br label %10, !llvm.loop !6

31:                                               ; preds = %10
  ret i32 0
}

declare i32 @__VERIFIER_nondet_ushort(...) #1

; Function Attrs: noreturn nounwind
declare void @abort() #2

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { noreturn nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { noreturn nounwind }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 1}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 14.0.0-1ubuntu1"}
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.mustprogress"}
