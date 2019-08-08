SRCPATH=`pwd`
echo "build cryptopp srcpath = $SRCPATH"
ANDROID_NDK="/root/android-ndk-r18b"
cp $ANDROID_NDK/sources/android/cpufeatures/cpu-features.h .
mkdir cbuild_android_v8
cd cbuild_android_v8
cmake \
    -D"CMAKE_MAKE_PROGRAM:PATH=/usr/bin/make" \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_NDK=$ANDROID_NDK \
    -DANDROID_ABI="arm64-v8a" \
    -DANDROID_PLATFORM="android-19" \
    -DANDROID_STL="c++_static" \
    -DCMAKE_INSTALL_PREFIX=$SRCPATH/build \
    -DCMAKE_BUILD_TYPE=Release \
    ..

make
make install

