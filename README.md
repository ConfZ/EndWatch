# EndWatch
EndWatch is a Non-termination oracle generation approach. By EndWatch, we can verify or detect non-termination for real world programs.
Please refer to our website for more information on our work and can also find the results of our experiment.
Webset of EndWatch: https://sites.google.com/view/endwatch/home


## How to use
Our method is realized in ./llvm-mode

### Build AFL and EndWatch wrapper:
```
$cd ProjectFile
$make
$cd llvm-mode
$make
```

### Testing on program

Build the project by our wrapper "afl-clang-fast" (c project), and "afl-clang-fast++" (c++ project).

For example for a case program.c
```
$./endwatch program.c
```
Then run afl-fuzz to fuzzing on the project.
```
$./afl-fuzz -i [input] -o [out] program.c
```
Finally, we can find the crash report for the project in [out] file.
