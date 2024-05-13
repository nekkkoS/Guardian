from conans import ConanFile, CMake, tools

class Guardian(ConanFile):
    name = "Guardian"
    version = "1.0.0"
    settings = "os" , "compiler", "build_type", "arch"
    generators = "cmake", "cmake_find_package"
    requires = [("nlohmann_json/3.10.5"), ("cryptopp/8.9.0")]