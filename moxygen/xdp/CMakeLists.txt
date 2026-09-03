# Copyright (c) Meta Platforms, Inc. and affiliates.
# This source code is licensed under the Apache 2.0 license found in the
# LICENSE file in the root directory of this source tree.

moxygen_add_library(moxygen_xdp
  SRCS
    XdpSocket.cpp
  DEPS
    libxdp
    libbpf
    
  EXPORTED_DEPS
    mvfst::mvfst_server_server
    Folly::folly_io_async_async_udp_socket
    Folly::folly_logging_logging
)