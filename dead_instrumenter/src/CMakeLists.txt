add_library(DeadInstrumentlib DeadInstrumenter.cpp)
target_include_directories(DeadInstrumentlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(DeadInstrumentlib PUBLIC clang-cpp)

add_subdirectory(tool)
