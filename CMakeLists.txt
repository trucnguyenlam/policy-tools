# minimum required CMAKE version
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

LIST( APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

# compiler must be 11 or 14
SET (CMAKE_CXX_STANDARD 11)
# SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
# SET(BUILD_SHARED_LIBRARIES OFF)
# SET(CMAKE_EXE_LINKER_FLAGS "-static")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")

# set variable pointing to the antlr tool that supports C++
# set(ANTLR4CPP_JAR_LOCATION ${PROJECT_SOURCE_DIR}/thirdparty/antlr/antlr-4.7-complete.jar)
# add external build for antlrcpp
include( ExternalAntlr4Cpp )
# add antrl4cpp artifacts to project environment
include_directories( ${ANTLR4CPP_INCLUDE_DIRS} )
link_directories( ${ANTLR4CPP_LIBS} )
message(STATUS "Found antlr4cpp libs: ${ANTLR4CPP_LIBS} and includes: ${ANTLR4CPP_INCLUDE_DIRS} ")

# Call macro to add lexer and grammar to your build dependencies.
# antlr4cpp_process_grammar(demo antlrcpptest
#   ${CMAKE_CURRENT_SOURCE_DIR}/TLexer.g4
#   ${CMAKE_CURRENT_SOURCE_DIR}/TParser.g4)
# # include generated files in project environment
# include_directories(${antlr4cpp_include_dirs_antlrcpptest})

include_directories(${PROJECT_SOURCE_DIR}/src)
# include_directories(${PROJECT_SOURCE_DIR}/src/parser/)

# FILE(GLOB generated_files ${PROJECT_SOURCE_DIR}/src/parser/*.cpp)
set(generated_files
    ${PROJECT_SOURCE_DIR}/src/parser/vacgrammarLexer.cpp
    ${PROJECT_SOURCE_DIR}/src/parser/vacgrammarParser.cpp
    ${PROJECT_SOURCE_DIR}/src/parser/vacgrammarBaseListener.cpp
    ${PROJECT_SOURCE_DIR}/src/parser/vacgrammarListener.cpp
    ${PROJECT_SOURCE_DIR}/src/parser/MyListener.cpp
    )

# export generated cpp files into list
foreach(generated_file ${generated_files})
list(APPEND antlr_generated_files ${generated_file})
set_source_files_properties(
  ${generated_file}
  PROPERTIES
  COMPILE_FLAGS -Wno-overloaded-virtual
  )
endforeach(generated_file)

set(SOURCES
    ${PROJECT_SOURCE_DIR}/src/parser/Logics.cpp
    ${PROJECT_SOURCE_DIR}/src/parser/Models.cpp
    ${PROJECT_SOURCE_DIR}/src/main.cpp
)

# add generated grammar to demo binary target
add_executable(vacparser ${SOURCES} ${antlr_generated_files})
add_dependencies(vacparser antlr4cpp)
target_link_libraries(vacparser antlr4-runtime)


# # Unit Test
# # Prepare "Catch" library for other executables
# set(CATCH_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/catch)
# add_library(Catch INTERFACE)
# target_include_directories(Catch INTERFACE ${CATCH_INCLUDE_DIR})

# # Make test executable
# set(TEST_SOURCES ${PROJECT_SOURCE_DIR}/tests/test.cpp)
# add_executable(tests ${TEST_SOURCES})
# target_link_libraries(tests Catch)
