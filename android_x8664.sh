SRCPATH=`pwd`
echo "build cryptopp srcpath = $SRCPATH"
ANDROID_NDK="/root/android-ndk-r18b"
cp $ANDROID_NDK/sources/android/cpufeatures/cpu-features.h .
mkdir cbuild_android_x8664
cd cbuild_android_x8664
cmake \
    -D"CMAKE_MAKE_PROGRAM:PATH=/usr/bin/make" \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_NDK=$ANDROID_NDK \
    -DLEGO_TRACE_MESSAGE=1 \
    -DANDROID_ABI="x86_64" \
    -DANDROID_PLATFORM="android-19" \
    -DANDROID_STL="c++_static" \
    -DCMAKE_INSTALL_PREFIX=$SRCPATH/build \
    -DCMAKE_BUILD_TYPE=Release \
    ..

make -j4
make install

