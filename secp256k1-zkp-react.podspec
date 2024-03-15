require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))
folly_compiler_flags = '-DFOLLY_NO_CONFIG -DFOLLY_MOBILE=1 -DFOLLY_USE_LIBCPP=1 -Wno-comma -Wno-shorten-64-to-32'

Pod::Spec.new do |s|
  s.name         = "secp256k1-zkp-react"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "10.0" }
  s.source       = { :git => "https://github.com/setavenger/Secp256k1-zkp-React-Native-Module.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm}", "cpp/**/*.{h,cpp}", "secp256k1-zkp-master/**/*.h", "secp256k1-zkp-master/src/secp256k1.c"

  s.pod_target_xcconfig = {
    "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/secp256k1-zkp-master\" \"$(PODS_TARGET_SRCROOT)/secp256k1-zkp-master/src\" \"$(PODS_TARGET_SRCROOT)/secp256k1-zkp-master/include\"",
    "GCC_PREPROCESSOR_DEFINITIONS" => "$(inherited) USE_ENDOMORPHISM USE_NUM_NONE USE_FIELD_INV_BUILTIN USE_SCALAR_INV_BUILTIN USE_FIELD_10X26 USE_SCALAR_8X32 USE_ECMULT_STATIC_PRECOMPUTATION ENABLE_MODULE_ECDH ENABLE_MODULE_GENERATOR ENABLE_MODULE_COMMITMENT ENABLE_MODULE_BULLETPROOF ENABLE_MODULE_AGGSIG"
  }

  s.dependency "React-Core"

  # Don't install the dependencies when we run `pod install` in the old architecture.
  if ENV['RCT_NEW_ARCH_ENABLED'] == '1' then
    s.compiler_flags = folly_compiler_flags + " -DRCT_NEW_ARCH_ENABLED=1 -D USE_ENDOMORPHISM -D USE_NUM_NONE -D USE_FIELD_INV_BUILTIN -D USE_SCALAR_INV_BUILTIN -D USE_FIELD_10X26 -D USE_SCALAR_8X32 -D USE_ECMULT_STATIC_PRECOMPUTATION -D ENABLE_MODULE_ECDH -D ENABLE_MODULE_GENERATOR -D ENABLE_MODULE_COMMITMENT -D ENABLE_MODULE_BULLETPROOF -D ENABLE_MODULE_AGGSIG"
    s.pod_target_xcconfig    = {
        "HEADER_SEARCH_PATHS" => "\"$(PODS_ROOT)/boost\" \"$(PODS_TARGET_SRCROOT)/secp256k1-zkp-master\" \"$(PODS_TARGET_SRCROOT)/secp256k1-zkp-master/src\" \"$(PODS_TARGET_SRCROOT)/secp256k1-zkp-master/include\"",
        "CLANG_CXX_LANGUAGE_STANDARD" => "c++17"
    }

    s.dependency "React-Codegen"
    s.dependency "RCT-Folly"
    s.dependency "RCTRequired"
    s.dependency "RCTTypeSafety"
    s.dependency "ReactCommon/turbomodule/core"
  end
end
