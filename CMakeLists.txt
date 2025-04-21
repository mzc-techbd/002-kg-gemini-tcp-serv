cmake_minimum_required(VERSION 3.11.0) # FetchContent requires 3.11+
project(tcp-server VERSION 0.1.0 LANGUAGES C CXX)

# Include FetchContent module
include(FetchContent)

# Set C++ standard (e.g., C++17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add an option for verbose logging (default OFF)
option(VERBOSE_LOG "Enable detailed verbose logging" OFF)

# Add an option to control which Gemini API method to use
option(USE_STREAMING_API "Use streamGenerateContent API (ON) vs generateContent API (OFF)" OFF) # Default changed to OFF

# Find required packages
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)
# Hint for Homebrew OpenSSL location on Apple Silicon
find_package(OpenSSL REQUIRED HINTS /opt/homebrew/opt/openssl /opt/homebrew)

# --- Fetch nlohmann/json ---
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.12.0 # Use a specific tag
)
FetchContent_MakeAvailable(nlohmann_json)
# --- End nlohmann_json ---

# --- Fetch spdlog ---
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.15.2 # Use a specific stable tag
)
FetchContent_MakeAvailable(spdlog)
# --- End spdlog ---

add_executable(tcp-server main.cpp)

# Add include directories
target_include_directories(tcp-server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} # For local headers if any
    ${nlohmann_json_SOURCE_DIR}/include # Add nlohmann_json include path
    # spdlog include directory is usually handled by target_link_libraries
)

# Add compile definition based on the CMake option
if(VERBOSE_LOG)
  target_compile_definitions(tcp-server PRIVATE ENABLE_VERBOSE_LOGGING)
  message(STATUS "Verbose logging enabled")
else()
   message(STATUS "Verbose logging disabled")
 endif()
if(USE_STREAMING_API)
  target_compile_definitions(tcp-server PRIVATE USE_STREAMING_API_CPP=1)
  message(STATUS "Using streamGenerateContent API")
else()
  target_compile_definitions(tcp-server PRIVATE USE_STREAMING_API_CPP=0)
  message(STATUS "Using generateContent API")
endif()

 # Link libraries
target_link_libraries(tcp-server PRIVATE
    CURL::libcurl
    Threads::Threads
    spdlog::spdlog               # Link spdlog
    nlohmann_json::nlohmann_json # Link nlohmann_json (FetchContent creates this target)
    OpenSSL::SSL         # Link OpenSSL libraries
    OpenSSL::Crypto
)