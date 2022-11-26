FROM ubuntu:18.04 as builder

# List of needed packages to be able to build kvazaar with autotools
ENV REQUIRED_PACKAGES automake autoconf libtool m4 build-essential git yasm pkgconf

COPY . kvazaar
# Run all the commands in one RUN so we don't have any extra history
# data in the image.
RUN apt-get update \
    && apt-get install -y $REQUIRED_PACKAGES \
    && cd kvazaar \
    && ./autogen.sh \
    && ./configure --disable-shared --prefix=/install\
    && make -j8\
    && make install \
    && AUTOINSTALLED_PACKAGES=`apt-mark showauto` \
    && apt-get remove --purge --force-yes -y $REQUIRED_PACKAGES $AUTOINSTALLED_PACKAGES \
    && apt-get autoremove -y \
    && rm -rf /var/lib/{apt,dpkg,cache,log}/
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang
RUN clang++ /kvazaar/mayhem/fuzz_kvz_get_scaled_qp.cpp -fsanitize=fuzzer,address -I /kvazaar/mayhem -L /install/lib/ -l:libkvazaar.a -o /fuzz


FROM ubuntu:18.04 as package
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_kvz_get_scaled_qp
