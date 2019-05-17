cmake_minimum_required(VERSION 3.8.2)

include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(dps_app)

include(ExternalProject)
find_package(Git REQUIRED)

set(dps_src_dir ${CMAKE_CURRENT_SOURCE_DIR}/../src)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../include")

add_compile_definitions(DPS_DEBUG=1)
add_compile_definitions(DPS_TARGET=DPS_TARGET_ZEPHYR)

set(dps_sources
    ${dps_src_dir}/ack.c
    ${dps_src_dir}/bitvec.c
    ${dps_src_dir}/cbor.c
    ${dps_src_dir}/coap.c
    ${dps_src_dir}/cose.c
    ${dps_src_dir}/dps.c
    ${dps_src_dir}/ec.c
    ${dps_src_dir}/err.c
    ${dps_src_dir}/gcm.c
    ${dps_src_dir}/hkdf.c
    ${dps_src_dir}/io_buf.c
    ${dps_src_dir}/keystore.c
    ${dps_src_dir}/keywrap.c
    ${dps_src_dir}/mbedtls.c
    ${dps_src_dir}/pub.c
    ${dps_src_dir}/sha2.c
    ${dps_src_dir}/sub.c
    ${dps_src_dir}/topics.c
    ${dps_src_dir}/uuid.c
    ${dps_src_dir}/zephyr/dbg.c
    ${dps_src_dir}/zephyr/entropy.c
    ${dps_src_dir}/zephyr/malloc.c
    ${dps_src_dir}/zephyr/network.c
    ${dps_src_dir}/zephyr/timer.c
)

target_sources(app PRIVATE ${dps_sources})

# The application to build
include_directories("../test")
target_sources(app PRIVATE "../test/keys.c")
target_sources(app PRIVATE "../test/sub_unit_test.c")

# For the mbedtls configuration file
zephyr_include_directories("${dps_src_dir}/zephyr")
