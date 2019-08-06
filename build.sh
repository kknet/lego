# configure
mkdir -p cbuild
cd cbuild
# CMAKE_BUILD_TYPE:
#   None:
#   Debug:              -g
#   Release:            -O3 -DNDEBUG
#   RelWithDebInfo:     -O2 -g -DNDEBUG
#   MinSizeRel:         -Os -DNDEBUG
cmake .. -DCMAKE_BUILD_TYPE=Debug -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl/1.0.2r -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=~/lego

# make
make lego -j4 
make vpn_proxy -j4 
make vpn_client -j4 
#make top_node

OS=`uname`
if [ "$OS" == "Darwin" ]
then
    mkdir -p libs
    find . -name "lib*.a" -and -not -name "libp2p.a"  -exec cp -f -- "{}" libs \;
fi
