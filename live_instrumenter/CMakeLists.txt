cmake_minimum_required(VERSION 3.19)
project(BranchInstrumenter LANGUAGES CXX)
# set(LLVM_CMAKE_DIR "/home/haoxin/disk-dut/research/compilers/llvm-project-old/build-clang-13/lib/cmake")  # @THX
set(CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH} "/home/haoxin/disk-dut/research/compilers/llvm-project-old/cmake/Modules")  # @THX
#find_package(LLVM REQUIRED CONFIG)

#message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
#message(STATUS "Using LLVMConfig.cmake in ${LLVM_DIR}")

#find_package(Clang REQUIRED CONFIG)
#message(STATUS "Using ClangConfig.cmake in ${Clang_DIR}")


#if(NOT "13" VERSION_EQUAL "${LLVM_VERSION_MAJOR}")
#  message(FATAL_ERROR "Found LLVM ${LLVM_VERSION_MAJOR}, but need LLVM 12")
#endif()


# set(_IMPORT_PREFIX "/home/haoxin/disk-dut/research/compilers/llvm-project-old/build-clang-13/lib")
# set(LLVM_CMAKE_DIR "/home/haoxin/disk-dut/research/compilers/llvm-project-old/build-clang-13/lib/cmake")  # @THX
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wpedantic -march=native")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_STANDARD 17)

#include_directories("/home/haoxin/disk-dut/research/compilers/llvm-project-old/build-clang-13/tools/clang/include/clang")
#include_directories("/home/haoxin/disk-dut/research/compilers/llvm-project-old/clang/include/clang")
link_directories("/home/haoxin/disk-dut/research/compilers/llvm-project-old/build-clang-13/lib")
link_directories("/usr/lib")
link_directories("/usr/local/lib")


#llvm-config --cxxflags
add_compile_options(-I/home/haoxin/disk-dut/research/compilers/llvm-project-old/build-clang-13/include -I/home/haoxin/disk-dut/research/compilers/llvm-project-old/build-clang-13/tools/clang/include/clang -std=c++14   -fno-exceptions -fno-rtti -D_GNU_SOURCE -D_DEBUG -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS)

#llvm-config --ldflags
LINK_LIBRARIES(-L/home/haoxin/disk-dut/research/compilers/llvm-project-old/build-clang-13/lib)

#llvm-config --system-libs
LINK_LIBRARIES(-lrt -ldl -lpthread -lm -lz -ltinfo -lxml2)

#llvm-config --libs
#LINK_LIBRARIES(-lLLVMWindowsManifest -lLLVMXRay -lLLVMLibDriver -lLLVMDlltoolDriver -lLLVMCoverage -lLLVMLineEditor -lLLVMXCoreDisassembler -lLLVMXCoreCodeGen -lLLVMXCoreDesc -lLLVMXCoreInfo -lLLVMX86Disassembler -lLLVMX86AsmParser -lLLVMX86CodeGen -lLLVMX86Desc -lLLVMX86Info -lLLVMWebAssemblyDisassembler -lLLVMWebAssemblyAsmParser -lLLVMWebAssemblyCodeGen -lLLVMWebAssemblyDesc -lLLVMWebAssemblyUtils -lLLVMWebAssemblyInfo -lLLVMSystemZDisassembler -lLLVMSystemZAsmParser -lLLVMSystemZCodeGen -lLLVMSystemZDesc -lLLVMSystemZInfo -lLLVMSparcDisassembler -lLLVMSparcAsmParser -lLLVMSparcCodeGen -lLLVMSparcDesc -lLLVMSparcInfo -lLLVMRISCVDisassembler -lLLVMRISCVAsmParser -lLLVMRISCVCodeGen -lLLVMRISCVDesc -lLLVMRISCVInfo -lLLVMPowerPCDisassembler -lLLVMPowerPCAsmParser -lLLVMPowerPCCodeGen -lLLVMPowerPCDesc -lLLVMPowerPCInfo -lLLVMNVPTXCodeGen -lLLVMNVPTXDesc -lLLVMNVPTXInfo -lLLVMMSP430Disassembler -lLLVMMSP430AsmParser -lLLVMMSP430CodeGen -lLLVMMSP430Desc -lLLVMMSP430Info -lLLVMMipsDisassembler -lLLVMMipsAsmParser -lLLVMMipsCodeGen -lLLVMMipsDesc -lLLVMMipsInfo -lLLVMLanaiDisassembler -lLLVMLanaiCodeGen -lLLVMLanaiAsmParser -lLLVMLanaiDesc -lLLVMLanaiInfo -lLLVMHexagonDisassembler -lLLVMHexagonCodeGen -lLLVMHexagonAsmParser -lLLVMHexagonDesc -lLLVMHexagonInfo -lLLVMBPFDisassembler -lLLVMBPFAsmParser -lLLVMBPFCodeGen -lLLVMBPFDesc -lLLVMBPFInfo -lLLVMAVRDisassembler -lLLVMAVRAsmParser -lLLVMAVRCodeGen -lLLVMAVRDesc -lLLVMAVRInfo -lLLVMARMDisassembler -lLLVMARMAsmParser -lLLVMARMCodeGen -lLLVMARMDesc -lLLVMARMUtils -lLLVMARMInfo -lLLVMAMDGPUDisassembler -lLLVMAMDGPUAsmParser -lLLVMAMDGPUCodeGen -lLLVMAMDGPUDesc -lLLVMAMDGPUUtils -lLLVMAMDGPUInfo -lLLVMAArch64Disassembler -lLLVMAArch64AsmParser -lLLVMAArch64CodeGen -lLLVMAArch64Desc -lLLVMAArch64Utils -lLLVMAArch64Info -lLLVMOrcJIT -lLLVMMCJIT -lLLVMJITLink -lLLVMInterpreter -lLLVMExecutionEngine -lLLVMRuntimeDyld -lLLVMOrcTargetProcess -lLLVMOrcShared -lLLVMDWP -lLLVMSymbolize -lLLVMDebugInfoPDB -lLLVMDebugInfoGSYM -lLLVMOption -lLLVMObjectYAML -lLLVMMCA -lLLVMMCDisassembler -lLLVMLTO -lLLVMPasses -lLLVMCFGuard -lLLVMCoroutines -lLLVMObjCARCOpts -lLLVMipo -lLLVMVectorize -lLLVMLinker -lLLVMInstrumentation -lLLVMFrontendOpenMP -lLLVMFrontendOpenACC -lLLVMExtensions -lLLVMDWARFLinker -lLLVMGlobalISel -lLLVMMIRParser -lLLVMAsmPrinter -lLLVMDebugInfoMSF -lLLVMDebugInfoDWARF -lLLVMSelectionDAG -lLLVMCodeGen -lLLVMIRReader -lLLVMAsmParser -lLLVMInterfaceStub -lLLVMFileCheck -lLLVMFuzzMutate -lLLVMTarget -lLLVMScalarOpts -lLLVMInstCombine -lLLVMAggressiveInstCombine -lLLVMTransformUtils -lLLVMBitWriter -lLLVMAnalysis -lLLVMProfileData -lLLVMObject -lLLVMTextAPI -lLLVMMCParser -lLLVMMC -lLLVMDebugInfoCodeView -lLLVMBitReader -lLLVMCore -lLLVMRemarks -lLLVMBitstreamReader -lLLVMBinaryFormat -lLLVMTableGen -lLLVMSupport -lLLVMDemangle)


if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
   add_compile_options (-fdiagnostics-color=always)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
   add_compile_options (-fcolor-diagnostics)
endif ()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_subdirectory(src)


IF (BUILD_TESTING)
    include(CTest)
    enable_testing()
    find_package(Catch2 REQUIRED)
    include(CTest)
    include(Catch)
    add_subdirectory(test)
ENDIF(BUILD_TESTING)
