from conans import ConanFile, CMake, tools

class Guardian(ConanFile):
    name = "Guardian"
    version = "1.0.0"
    settings = "os" , "compiler", "build_type", "arch"
    generators = "cmake", "cmake_find_package"
    requires = [("nlohmann_json/3.10.5"), ("cryptopp/8.9.0")]

    def source(self):
        print("source")
        git = tools.Git(self.source_folder)
        git.clone("https://github.com/nekkkoS/Guardian.git", "main")
        git.checkout_submodules("recursive")

    def build(self):
        print("built")
        cmake_release = CMake(self)
        cmake_release.configure()
        cmake_release.build()

    def package(self):
        print("package")
        self.copy("*.h", dst="inc", keep_path=False)
        self.copy("*.hpp", src="Guardian/inc", dst="inc", keep_path=True)
        self.copy("*.a", dst="lib", keep_path=False)
        self.copy("*.lib", dst="lib", keep_path=False)

    def package_info(self):
        print("package_into")
        self.cpp_info.includedirs = ["inc"]
        self.cpp_info.libs = ["Guardian"]
        self.cpp_info.libdirs = ["lib"]