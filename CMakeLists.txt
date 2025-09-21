cmake_minimum_required(VERSION 3.16)
project(psp_plugin C)

# Ensure we can find OpenSSL’s crypto
find_package(OpenSSL REQUIRED)

# Register 'psp' as a VPP plugin
add_vpp_plugin(psp
  SOURCES
    psp_enc_node.c
    psp_dec_node.c

  INSTALL_HEADERS
    psp.h

)