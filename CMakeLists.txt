# -*- cmake -*-
#
# Copyright 2023 Dmitry Igrishin
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.22)
cmake_policy(VERSION 3.22)
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
  cmake_policy(SET CMP0135 NEW)
endif()
project(openssh_portable)

if (NOT (UNIX OR WIN32))
  message(FATAL_ERROR "Unsupported platform")
endif()

# ------------------------------------------------------------------------------
# Build options
# ------------------------------------------------------------------------------

set(CMAKE_VERBOSE_MAKEFILE On CACHE BOOL
  "Verbose output upon build?" FORCE)

set(OPENSSH_PORTABLE_WITH_OPENSSL On CACHE BOOL
  "Build with OpenSSL?")

if(NOT DEFINED CMAKE_BUILD_TYPE OR NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING
    "Build type: Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

# ------------------------------------------------------------------------------
# Languages
# ------------------------------------------------------------------------------

enable_language(C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED On)

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

# Use the super build approach.
include(ExternalProject)

set(common_cmake_args
  "-DBUILD_SHARED_LIBS=Off"
)

#
# Zlib
#
set(zlib_source_dir "${CMAKE_CURRENT_SOURCE_DIR}/contrib/deps/zlib")
set(zlib_patch_dir "${CMAKE_CURRENT_SOURCE_DIR}/contrib/deps/_patch/zlib")
set(zlib_install_dir "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/zlib")
set(zlib_cmake_args ${common_cmake_args}
  "-DCMAKE_INSTALL_PREFIX=${zlib_install_dir}"
)
ExternalProject_Add(zlib
  URL https://zlib.net/zlib-1.2.13.tar.gz
  URL_HASH SHA256=b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30
  DOWNLOAD_NO_PROGRESS False
  INACTIVITY_TIMEOUT 60
  CMAKE_ARGS ${zlib_cmake_args}
  DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}"
  SOURCE_DIR "${zlib_source_dir}"
  INSTALL_DIR "${zlib_install_dir}"
  BUILD_IN_SOURCE False
  PATCH_COMMAND cmake -E copy_if_different
  "${zlib_patch_dir}/CMakeLists-1.2.13.txt" "${zlib_source_dir}/CMakeLists.txt"
)
if(WIN32)
  set(zlib_static "${zlib_install_dir}/lib/zlibstatic.lib")
else()
  set(zlib_static "${zlib_install_dir}/lib/libz.a")
endif()
set(zlib_include_dir "${zlib_install_dir}/include")
set(zlib_library_dir "${zlib_install_dir}/lib")

#
# LibreSSL
#
set(libressl_install_dir "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/libressl")
set(libressl_cmake_args ${common_cmake_args}
  "-DCMAKE_INSTALL_PREFIX=${libressl_install_dir}")
ExternalProject_Add(libressl
  URL https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.7.2.tar.gz
  URL_HASH SHA256=b06aa538fefc9c6b33c4db4931a09a5f52d9d2357219afcbff7d93fe12ebf6f7
  DOWNLOAD_NO_PROGRESS False
  INACTIVITY_TIMEOUT 60
  CMAKE_ARGS ${libressl_cmake_args}
  DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}"
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/contrib/deps/libressl"
  INSTALL_DIR "${libressl_install_dir}"
  BUILD_IN_SOURCE False
)
if(WIN32)
  set(ssl_crypto_static
    "${libressl_install_dir}/lib/crypto-50.lib"
    Bcrypt.lib # for BCryptGenRandom()
    Ws2_32.lib
  )
  set(ssl_ssl_static "${libressl_install_dir}/lib/ssl-53.lib")
  set(ssl_tls_static "${libressl_install_dir}/lib/tls-26.lib")
else()
  set(ssl_crypto_static "${libressl_install_dir}/lib/libcrypto.a")
  set(ssl_ssl_static "${libressl_install_dir}/lib/libssl.a")
  set(ssl_tls_static "${libressl_install_dir}/lib/libtls.a")
endif()
set(ssl_include_dir "${libressl_install_dir}/include")
set(ssl_library_dir "${libressl_install_dir}/lib")

#
# libcbor
#
set(libcbor_install_dir "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/libcbor")
set(libcbor_cmake_args ${common_cmake_args}
  "-DCMAKE_INSTALL_PREFIX=${libcbor_install_dir}")
ExternalProject_Add(libcbor
  URL https://github.com/PJK/libcbor/archive/refs/tags/v0.10.2.tar.gz
  URL_HASH SHA256=e75f712215d7b7e5c89ef322a09b701f7159f028b8b48978865725f00f79875b
  DOWNLOAD_NO_PROGRESS False
  INACTIVITY_TIMEOUT 60
  CMAKE_ARGS ${libcbor_cmake_args}
  DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}"
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/contrib/deps/libcbor"
  INSTALL_DIR "${libcbor_install_dir}"
  BUILD_IN_SOURCE False
)
if(WIN32)
  set(libcbor_static "${libcbor_install_dir}/lib/cbor.lib")
else()
  set(libcbor_static "${libcbor_install_dir}/lib/libcbor.a")
endif()
set(libcbor_include_dir "${libcbor_install_dir}/include")
set(libcbor_library_dir "${libcbor_install_dir}/lib")

#
# libfido2
#
set(libfido2_install_dir "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/libfido2")
set(libfido2_cmake_prefix_path
  ${libcbor_install_dir}
  ${libressl_install_dir}
  ${zlib_install_dir})
# Hack to pass CMAKE_PREFIX_PATH and others as lists (part 1/2)
string(REPLACE ";" "|" libfido2_cmake_prefix_path "${libfido2_cmake_prefix_path}")
if(WIN32)
  string(REPLACE ";" "|" ssl_crypto_static_str "${ssl_crypto_static}")
endif()
set(libfido2_cmake_args ${common_cmake_args}
  "-DCMAKE_INSTALL_PREFIX=${libfido2_install_dir}"
  "-DCBOR_INCLUDE_DIRS=${libcbor_include_dir}"
  "-DCBOR_LIBRARY_DIRS=${libcbor_library_dir}"
  "-DCRYPTO_INCLUDE_DIRS=${ssl_include_dir}"
  "-DCRYPTO_LIBRARY_DIRS=${ssl_library_dir}"
  "-DZLIB_INCLUDE_DIRS=${zlib_include_dir}"
  "-DZLIB_LIBRARY_DIRS=${zlib_library_dir}"
  "-DCBOR_LIBRARIES=${libcbor_static}"
  "-DCRYPTO_LIBRARIES=${ssl_crypto_static_str}"
  "-DZLIB_LIBRARIES=${zlib_static}"
)
if(UNIX)
  list(APPEND libfido2_cmake_args
    "-DPKG_CONFIG_USE_CMAKE_PREFIX_PATH=True"
    "-DCMAKE_PREFIX_PATH=${libfido2_cmake_prefix_path}"
  )
endif()
ExternalProject_Add(libfido2
  DEPENDS zlib libressl libcbor
  URL https://developers.yubico.com/libfido2/Releases/libfido2-1.13.0.tar.gz
  URL_HASH SHA256=51d43727e2a1c4544c7fd0ee47786f443e39f1388ada735a509ad4af0a2459ca
  DOWNLOAD_NO_PROGRESS False
  INACTIVITY_TIMEOUT 60
  LIST_SEPARATOR | # Hack to pass CMAKE_PREFIX_PATH and others as lists (part 2/2)
  CMAKE_ARGS ${libfido2_cmake_args}
  DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}"
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/contrib/deps/libfido2"
  INSTALL_DIR "${libfido2_install_dir}"
  BUILD_IN_SOURCE False
)
if(WIN32)
  set(libfido2_static "${libfido2_install_dir}/lib/fido2_static.lib")
else()
  set(libfido2_static "${libfido2_install_dir}/lib/libfido2.a")
endif()
set(libfido2_include_dir "${libfido2_install_dir}/include")

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

if(WIN32)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config-windows.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/config.h @ONLY NEWLINE_STYLE UNIX)
else()
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config-default.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/config.h NEWLINE_STYLE UNIX)
endif()

# --------------------
# openssh_posix_compat
# --------------------

if(WIN32)
  set(openssh_posix_compat_src
    contrib/win32/win32compat/w32fd.c
    contrib/win32/win32compat/signal.c
    contrib/win32/win32compat/socketio.c
    contrib/win32/win32compat/fileio.c
    contrib/win32/win32compat/termio.c
    contrib/win32/win32compat/misc.c
    contrib/win32/win32compat/signal_sigalrm.c
    contrib/win32/win32compat/signal_sigchld.c
    contrib/win32/win32compat/w32api_proxies.c
    contrib/win32/win32compat/win32_usertoken_utils.c
    contrib/win32/win32compat/w32log.c
    contrib/win32/win32compat/pwd.c
    contrib/win32/win32compat/win32_dirent.c
    contrib/win32/win32compat/no-ops.c
    contrib/win32/win32compat/ansiprsr.c
    contrib/win32/win32compat/console.c
    contrib/win32/win32compat/tncon.c
    contrib/win32/win32compat/tnnet.c
    contrib/win32/win32compat/utf.c
    contrib/win32/win32compat/spawn.c
    contrib/win32/win32compat/signal_wait.c
    contrib/win32/win32compat/win32_pty.c
    contrib/win32/win32compat/gss-sspi.c
    contrib/win32/openssh/sshTelemetry.c
  )

  set(openssh_posix_compat_inc
    contrib/win32/win32compat/w32fd.h
    contrib/win32/win32compat/inc/fcntl.h
    contrib/win32/win32compat/inc/signal.h
    contrib/win32/win32compat/inc/sys/select.h
    contrib/win32/win32compat/inc/sys/socket.h
    contrib/win32/win32compat/inc/sys/stat.h
    contrib/win32/win32compat/inc/sys/time.h
    contrib/win32/win32compat/inc/sys/wait.h
    contrib/win32/win32compat/inc/unistd.h
    contrib/win32/win32compat/inc/poll.h
    contrib/win32/win32compat/inc/sys/statvfs.h
    contrib/win32/win32compat/inc/dlfcn.h
    contrib/win32/win32compat/inc/syslog.h
    contrib/win32/win32compat/signal_internal.h
    contrib/win32/win32compat/inc/utf.h
    contrib/win32/win32compat/inc/arpa/inet.h
    contrib/win32/win32compat/inc/arpa/nameser.h
    contrib/win32/win32compat/inc/grp.h
    contrib/win32/win32compat/inc/libgen.h
    contrib/win32/win32compat/inc/netdb.h
    contrib/win32/win32compat/inc/netinet/in.h
    contrib/win32/win32compat/inc/netinet/in_systm.h
    contrib/win32/win32compat/inc/netinet/ip.h
    contrib/win32/win32compat/inc/netinet/tcp.h
    contrib/win32/win32compat/inc/resolv.h
    contrib/win32/win32compat/inc/sys/ioctl.h
    contrib/win32/win32compat/inc/sys/resource.h
    contrib/win32/win32compat/inc/sys/uio.h
    contrib/win32/win32compat/inc/sys/un.h
    contrib/win32/win32compat/inc/termios.h
    contrib/win32/win32compat/inc/dirent.h
    contrib/win32/win32compat/inc/pwd.h
    contrib/win32/win32compat/misc_internal.h
    contrib/win32/win32compat/inc/stdio.h
    contrib/win32/win32compat/inc/string.h
    contrib/win32/win32compat/inc/strings.h
    contrib/win32/win32compat/inc/sys/types.h
    contrib/win32/win32compat/inc/ctype.h
    contrib/win32/win32compat/inc/stdlib.h
    contrib/win32/win32compat/debug.h
    contrib/win32/win32compat/console.h
    contrib/win32/win32compat/tnnet.h
    contrib/win32/win32compat/inc/spawn.h
    contrib/win32/win32compat/inc/net/if.h
    contrib/win32/win32compat/inc/time.h
    contrib/win32/win32compat/inc/gssapi.h
    contrib/win32/openssh/MicrosoftTelemetry.h
    contrib/win32/openssh/sshTelemetry.h
    contrib/win32/openssh/sshTelemetryInternal.h
  )

  set_source_files_properties(${openssh_posix_compat_src}
    PROPERTIES LANGUAGE "C")
endif()

# ----------------------
# openssh_openbsd_compat
# ----------------------

set(openssh_openbsd_compat_src
  openbsd-compat/arc4random.c
  openbsd-compat/base64.c
  openbsd-compat/basename.c
  openbsd-compat/bcrypt_pbkdf.c
  openbsd-compat/bindresvport.c
  openbsd-compat/blowfish.c
  openbsd-compat/bsd-asprintf.c
  openbsd-compat/bsd-closefrom.c
  openbsd-compat/bsd-cygwin_util.c
  openbsd-compat/bsd-getline.c
  openbsd-compat/bsd-getpagesize.c
  openbsd-compat/bsd-getpeereid.c
  openbsd-compat/bsd-misc.c
  openbsd-compat/bsd-nextstep.c
  openbsd-compat/bsd-openpty.c
  openbsd-compat/bsd-poll.c
  openbsd-compat/bsd-setres_id.c
  openbsd-compat/bsd-snprintf.c
  openbsd-compat/bsd-statvfs.c
  openbsd-compat/bsd-waitpid.c
  openbsd-compat/daemon.c
  openbsd-compat/dirname.c
  openbsd-compat/explicit_bzero.c
  openbsd-compat/fake-rfc2553.c
  openbsd-compat/fmt_scaled.c
  openbsd-compat/getcwd.c
  openbsd-compat/getgrouplist.c
  openbsd-compat/getopt_long.c
  openbsd-compat/inet_aton.c
  openbsd-compat/inet_ntoa.c
  openbsd-compat/inet_ntop.c
  openbsd-compat/kludge-fd_set.c
  # Stuff from libressl-api-compat.c are already defined in ssl_crypto_static.
  # openbsd-compat/libressl-api-compat.c
  openbsd-compat/md5.c
  openbsd-compat/memmem.c
  openbsd-compat/mktemp.c
  openbsd-compat/openssl-compat.c
  openbsd-compat/port-irix.c
  openbsd-compat/port-linux.c
  openbsd-compat/port-solaris.c
  openbsd-compat/port-net.c
  openbsd-compat/port-uw.c
  openbsd-compat/readpassphrase.c
  openbsd-compat/reallocarray.c
  openbsd-compat/recallocarray.c
  openbsd-compat/rresvport.c
  openbsd-compat/setenv.c
  openbsd-compat/setproctitle.c
  openbsd-compat/sha1.c
  openbsd-compat/sha2.c
  openbsd-compat/strlcat.c
  openbsd-compat/strlcpy.c
  openbsd-compat/strmode.c
  openbsd-compat/strptime.c
  openbsd-compat/strsep.c
  openbsd-compat/strtoll.c
  openbsd-compat/strtonum.c
  openbsd-compat/strtoul.c
  openbsd-compat/strtoull.c
  openbsd-compat/timingsafe_bcmp.c
  openbsd-compat/vis.c
  openbsd-compat/xcrypt.c
  openbsd-compat/glob.c
  openbsd-compat/strcasestr.c
  openbsd-compat/strndup.c
  openbsd-compat/bsd-pselect.c
)
if(WIN32)
  list(APPEND openssh_openbsd_compat_src
    openbsd-compat/getrrsetbyname-ldns.c
  )
elseif(UNIX)
  list(APPEND openssh_openbsd_compat_src
    openbsd-compat/arc4random_uniform.c
    openbsd-compat/pwcache.c
    openbsd-compat/bsd-getentropy.c
    openbsd-compat/getrrsetbyname.c
  )
endif()

set(openssh_openbsd_compat_inc
  openbsd-compat/base64.h
  openbsd-compat/blf.h
  openbsd-compat/bsd-cygwin_util.h
  openbsd-compat/bsd-misc.h
  openbsd-compat/bsd-nextstep.h
  openbsd-compat/bsd-poll.h
  openbsd-compat/bsd-setres_id.h
  openbsd-compat/bsd-statvfs.h
  openbsd-compat/bsd-waitpid.h
  openbsd-compat/chacha_private.h
  openbsd-compat/charclass.h
  openbsd-compat/fake-rfc2553.h
  openbsd-compat/getopt.h
  openbsd-compat/getrrsetbyname.h
  openbsd-compat/glob.h
  openbsd-compat/md5.h
  openbsd-compat/openbsd-compat.h
  openbsd-compat/openssl-compat.h
  openbsd-compat/port-aix.h
  openbsd-compat/port-irix.h
  openbsd-compat/port-linux.h
  openbsd-compat/port-solaris.h
  openbsd-compat/port-net.h
  openbsd-compat/port-uw.h
  openbsd-compat/readpassphrase.h
  openbsd-compat/sha1.h
  openbsd-compat/sha2.h
  openbsd-compat/sys-queue.h
  openbsd-compat/sys-tree.h
  openbsd-compat/vis.h
)

set_source_files_properties(${openssh_openbsd_compat_src}
  PROPERTIES LANGUAGE "C")

# --------------
# openssh_libssh
# --------------

set(openssh_libssh_src
  addr.c
  addrmatch.c
  atomicio.c
  authfd.c
  authfile.c
  bitmap.c
  canohost.c
  chacha.c
  channels.c
  cipher-aes.c
  cipher-aesctr.c
  cipher-chachapoly.c
  cipher.c
  cleanup.c
  compat.c
  dispatch.c
  dns.c
  ed25519.c
  entropy.c
  fatal.c
  gss-genr.c
  hash.c
  hmac.c
  hostfile.c
  kex.c
  kexc25519.c
  kexgen.c
  kexsntrup761x25519.c
  krl.c
  log.c
  mac.c
  match.c
  misc.c
  moduli.c
  monitor_fdpass.c
  msg.c
  nchan.c
  packet.c
  poly1305.c
  progressmeter.c
  readpass.c
  rijndael.c
  smult_curve25519_ref.c
  sntrup761.c
  ssh-ed25519.c
  ssh-pkcs11.c
  sshbuf-getput-basic.c
  sshbuf-getput-crypto.c
  sshbuf-misc.c
  sshbuf.c
  ssherr.c
  sshkey.c
  ssh_api.c
  umac.c
  xmalloc.c
  platform-misc.c
  platform-pledge.c
  platform-tracing.c
  platform.c
  sandbox-pledge.c
  kexgexs.c
  ssh-ecdsa-sk.c
  ssh-ed25519-sk.c
  ssh-sk.c
  sshbuf-io.c
  cipher-chachapoly-libcrypto.c
)
if(WIN32)
  list(APPEND openssh_libssh_src
    contrib/win32/win32compat/ttymodes_windows.c
    contrib/win32/win32compat/w32-sshfileperm.c
    contrib/win32/win32compat/spawn-ext.c
  )
elseif(UNIX)
  list(APPEND openssh_libssh_src
    umac128.c
  )
endif()
if(OPENSSH_PORTABLE_WITH_OPENSSL)
  list(APPEND openssh_libssh_src
    dh.c
    kexdh.c
    kexecdh.c
    kexgex.c
    kexgexc.c
    ssh-dss.c
    ssh-ecdsa.c
    ssh-rsa.c
    digest-openssl.c
  )
else()
  list(APPEND openssh_libssh_src
    digest-libc.c
  )
endif()

set(openssh_libssh_inc
  sshfileperm.h
)

set_source_files_properties(${openssh_libssh_src}
  PROPERTIES LANGUAGE "C")

# ------------
# openssh_sshd
# ------------

set(openssh_sshd_src
  audit-bsm.c
  audit-linux.c
  audit.c
  auth-bsdauth.c
  auth-krb5.c
  auth-options.c
  auth-pam.c
  auth-passwd.c
  auth-rhosts.c
  auth-shadow.c
  auth-sia.c
  auth.c
  auth2-chall.c
  auth2-gss.c
  auth2-hostbased.c
  auth2-kbdint.c
  auth2-none.c
  auth2-passwd.c
  auth2-pubkey.c
  auth2.c
  gss-serv-krb5.c
  gss-serv.c
  loginrec.c
  monitor.c
  monitor_wrap.c
  platform.c
  sandbox-capsicum.c
  sandbox-darwin.c
  sandbox-null.c
  sandbox-rlimit.c
  sandbox-seccomp-filter.c
  sandbox-systrace.c
  servconf.c
  serverloop.c
  session.c
  sftp-common.c
  sshd.c
  sshlogin.c
  auth2-pubkeyfile.c
  misc.c
  srclimit.c
  ssh-sk-client.c
  sshkey.c
)
if(WIN32)
  list(APPEND openssh_sshd_src
    contrib/win32/win32compat/win32_groupaccess.c
    contrib/win32/win32compat/win32_sshpty.c
    contrib/win32/win32compat/wmain_sshd.c
    contrib/win32/win32compat/w32-doexec.c
    contrib/win32/win32compat/win32-utf8.c
  )
elseif(UNIX)
  list(APPEND openssh_sshd_src
    groupaccess.c
    uidswap.c
    ttymodes.c
    umac128.c
    sshpty.c
    sftp-server.c
    sftp-realpath.c
    utf8.c
  )
endif()

set_source_files_properties(${openssh_sshd_src}
  PROPERTIES LANGUAGE "C")

# ------------------
# openssh_ssh_keygen
# ------------------

set(openssh_ssh_keygen_src
  ssh-keygen.c
  sshsig.c
  ssh-sk-client.c
)
if(WIN32)
  list(APPEND openssh_ssh_keygen_src
    contrib/win32/win32compat/wmain_common.c
    contrib/win32/win32compat/win32-utf8.c
  )
elseif(UNIX)
  list(APPEND openssh_ssh_keygen_src
    utf8.c
  )
endif()

set_source_files_properties(${openssh_ssh_keygen_src}
  PROPERTIES LANGUAGE "C")

# -----------
# openssh_scp
# -----------

set(openssh_scp_src
  scp.c
  sftp-client.c
  sftp-common.c
  sftp-glob.c
  sftp-usergroup.c
)
if(WIN32)
  list(APPEND openssh_scp_src
    contrib/win32/win32compat/wmain_common.c
    contrib/win32/win32compat/win32-utf8.c
  )
elseif(UNIX)
  list(APPEND openssh_scp_src
    utf8.c
  )
endif()

set_source_files_properties(${openssh_scp_src}
  PROPERTIES LANGUAGE "C")

# -------------------
# openssh_sftp_server
# -------------------

set(openssh_sftp_server_src
  sftp-common.c
  sftp-server-main.c
  sftp-server.c
)
if(WIN32)
  list(APPEND openssh_sftp_server_src
    contrib/win32/win32compat/wmain_common.c
  )
elseif(UNIX)
  list(APPEND openssh_sftp_server_src
    sftp-realpath.c
  )
endif()

set_source_files_properties(${openssh_sftp_server_src}
  PROPERTIES LANGUAGE "C")

# ------------
# openssh_sftp
# ------------

set(openssh_sftp_src
  progressmeter.c
  sftp-client.c
  sftp-common.c
  sftp-glob.c
  sftp.c
  sftp-usergroup.c
)
if(WIN32)
  list(APPEND openssh_sftp_src
    contrib/win32/win32compat/wmain_common.c
    contrib/win32/win32compat/win32-utf8.c
  )
elseif(UNIX)
  list(APPEND openssh_sftp_src
    utf8.c
  )
endif()

set_source_files_properties(${openssh_sftp_src}
  PROPERTIES LANGUAGE "C")

# ---------------
# openssh_ssh_add
# ---------------

set(openssh_ssh_add_src
  ssh-add.c
  ssh-sk-client.c
)
if(WIN32)
  list(APPEND openssh_ssh_add_src
    contrib/win32/win32compat/wmain_common.c
    contrib/win32/win32compat/win32-utf8.c
  )
elseif(UNIX)
  list(APPEND openssh_ssh_add_src
    utf8.c
  )
endif()

set_source_files_properties(${openssh_ssh_add_src}
  PROPERTIES LANGUAGE "C")

# -----------------
# openssh_ssh_agent
# -----------------

set(openssh_ssh_agent_src
  ssh-pkcs11-client.c
  ssh-sk-client.c
)
if(WIN32)
  list(APPEND openssh_ssh_agent_src
    contrib/win32/win32compat/ssh-agent/agent-main.c
    contrib/win32/win32compat/ssh-agent/agent.c
    contrib/win32/win32compat/ssh-agent/connection.c
    contrib/win32/win32compat/ssh-agent/keyagent-request.c
  )
elseif(UNIX)
  list(APPEND openssh_ssh_agent_src
    ssh-agent.c
  )
endif()

if(WIN32)
  set(openssh_ssh_agent_inc
    contrib/win32/win32compat/ssh-agent/agent-request.h
    contrib/win32/win32compat/ssh-agent/agent.h
  )
endif()

set_source_files_properties(${openssh_ssh_agent_src}
  PROPERTIES LANGUAGE "C")

# -------------------
# openssh_ssh_keyscan
# -------------------

set(openssh_ssh_keyscan_src
  ssh-keyscan.c
  ssh-sk-client.c
)
if(WIN32)
  list(APPEND openssh_ssh_keyscan_src
    contrib/win32/win32compat/wmain_common.c
  )
elseif(UNIX)
  list(APPEND openssh_ssh_keyscan_src
    ssh-keyscan.c
  )
endif()

set_source_files_properties(${openssh_ssh_keyscan_src}
  PROPERTIES LANGUAGE "C")

# -------------------------
# openssh_ssh_pkcs11_helper
# -------------------------

set(openssh_ssh_pkcs11_helper_src
  ssh-pkcs11-helper.c
  ssh-pkcs11.c
  ssh-sk-client.c
)
if(WIN32)
  list(APPEND openssh_ssh_pkcs11_helper_src
    contrib/win32/win32compat/wmain_common.c
  )
endif()

set_source_files_properties(${openssh_ssh_pkcs11_helper_src}
  PROPERTIES LANGUAGE "C")

# ---------------------
# openssh_ssh_shellhost
# ---------------------

if(WIN32)
  set(openssh_ssh_shellhost_src
    contrib/win32/win32compat/shell-host.c
    contrib/win32/win32compat/utf.c
  )
  set_source_files_properties(${openssh_ssh_shellhost_src}
    PROPERTIES LANGUAGE "C")
endif()

# ---------------------
# openssh_ssh_sk_helper
# ---------------------

set(openssh_ssh_sk_helper_src
  ssh-sk-helper.c
  ssh-sk.c
  sk-usbhid.c
)
if(WIN32)
  list(APPEND openssh_ssh_sk_helper_src
    contrib/win32/win32compat/wmain_common.c
  )
elseif(UNIX)
  list(APPEND openssh_ssh_sk_helper_src
    ssh-sk-helper.c
  )
endif()

set_source_files_properties(${openssh_ssh_sk_helper_src}
  PROPERTIES LANGUAGE "C")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

# --------------------
# openssh_posix_compat
# --------------------

if(WIN32)
  add_library(openssh_posix_compat
    ${openssh_posix_compat_inc} ${openssh_posix_compat_src})
  set_target_properties(openssh_posix_compat PROPERTIES
    LANGUAGE "C"
    LINKER_LANGUAGE "C"
    POSITION_INDEPENDENT_CODE True
  )
  target_link_libraries(openssh_posix_compat PUBLIC
    Crypt32.lib
    Shlwapi.lib
    Secur32.lib
    Userenv.lib
    Ws2_32.lib
  )
  target_compile_definitions(openssh_posix_compat PUBLIC
    USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    _CRT_DECLARE_NONSTDC_NAMES=0
    HAVE_SETENV   # FIX C4273
    HAVE_UNSETENV # FIX C4273
  )
endif()

# ----------------------
# openssh_openbsd_compat
# ----------------------

add_library(openssh_openbsd_compat
  ${openssh_openbsd_compat_inc} ${openssh_openbsd_compat_src})
add_dependencies(openssh_openbsd_compat libressl)
set_target_properties(openssh_openbsd_compat PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
  POSITION_INDEPENDENT_CODE True
)

target_include_directories(openssh_openbsd_compat PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/openbsd-compat
  ${ssl_include_dir}
)
target_link_libraries(openssh_openbsd_compat PUBLIC
  ${ssl_crypto_static}
)

if(WIN32)
  target_include_directories(openssh_openbsd_compat PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_openbsd_compat PUBLIC
    USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS

    HAVE_STRNLEN  # FIX C4273
    # HAVE_SETENV   # FIX C4273
    # HAVE_UNSETENV # FIX C4273
  )
elseif(UNIX)
  target_link_libraries(openssh_openbsd_compat PUBLIC
    crypt
  )
endif()

# --------------
# openssh_libssh
# --------------

add_library(openssh_libssh
  ${openssh_libssh_inc} ${openssh_libssh_src})
add_dependencies(openssh_libssh libressl zlib)
set_target_properties(openssh_libssh PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
  POSITION_INDEPENDENT_CODE True
)

target_include_directories(openssh_libssh PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${ssl_include_dir}
  ${zlib_include_dir}
)

target_link_libraries(openssh_libssh PUBLIC
  ${ssl_crypto_static}
  ${zlib_static}
)

if(WIN32)
  target_include_directories(openssh_libssh PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )

  target_link_libraries(openssh_libssh PUBLIC
    Ws2_32.lib
  )

  target_compile_definitions(openssh_libssh PUBLIC
    USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS

    HAVE_STRNLEN  # FIX C4273
  )
endif()

# ------------
# openssh_sshd
# ------------

add_executable(openssh_sshd ${openssh_sshd_src})
add_dependencies(openssh_sshd libfido2)
set_target_properties(openssh_sshd PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
)

target_include_directories(openssh_sshd PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(openssh_sshd PRIVATE
  openssh_libssh
  openssh_openbsd_compat
  ${libfido2_static}
)

if(WIN32)
  target_include_directories(openssh_sshd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_sshd PRIVATE
    USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    # _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )
  target_compile_options(openssh_sshd PRIVATE
    # /Gy
    # /Qspectre
  )
  target_link_options(openssh_sshd PRIVATE
    /entry:wmainCRTStartup
    /force:multiple
    /opt:ref
    /opt:icf
    /incremental:no
    /ignore:4099
  )
  target_link_libraries(openssh_sshd PRIVATE
    openssh_posix_compat
  )
elseif(UNIX)
  target_link_libraries(openssh_sshd PRIVATE
    bsd # for freezero()
  )
endif()

# ------------------
# openssh_ssh_keygen
# ------------------

add_executable(openssh_ssh_keygen ${openssh_ssh_keygen_src})
set_target_properties(openssh_ssh_keygen PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
)

target_include_directories(openssh_ssh_keygen PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${ssl_include_dir}
)

target_link_libraries(openssh_ssh_keygen PRIVATE
  openssh_libssh
  openssh_openbsd_compat
)

if(WIN32)
  target_include_directories(openssh_ssh_keygen PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_ssh_keygen PRIVATE
    # USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    # _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )
  target_compile_options(openssh_ssh_keygen PRIVATE
    # /Gy
  )
  target_link_options(openssh_ssh_keygen PRIVATE
    /entry:wmainCRTStartup
    # /force:multiple
    # /opt:ref
    # /opt:icf
    # /incremental:no
  )
  target_link_libraries(openssh_ssh_keygen PRIVATE
    openssh_posix_compat
    ${ssl_crypto_static}
  )
elseif(UNIX)
  target_link_libraries(openssh_ssh_keygen PRIVATE
    bsd # for freezero()
  )
endif()

# -----------
# openssh_scp
# -----------

add_executable(openssh_scp ${openssh_scp_src})
set_target_properties(openssh_scp PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
)

target_include_directories(openssh_scp PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(openssh_scp PRIVATE
  openssh_libssh
  openssh_openbsd_compat
)

if(WIN32)
  target_include_directories(openssh_scp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_scp PRIVATE
    # USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    # _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )
  target_compile_options(openssh_scp PRIVATE
    # /Gy
    # /Qspectre
  )
  target_link_options(openssh_scp PRIVATE
    /entry:wmainCRTStartup
    # /force:multiple
    # /opt:ref
    # /opt:icf
    # /incremental:no
  )
  target_link_libraries(openssh_scp PRIVATE
    openssh_posix_compat
  )
elseif(UNIX)
  target_link_libraries(openssh_scp PRIVATE
    bsd # for freezero()
  )
endif()

# -------------------
# openssh_sftp_server
# -------------------

add_executable(openssh_sftp_server ${openssh_sftp_server_src})
set_target_properties(openssh_sftp_server PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
)

target_include_directories(openssh_sftp_server PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(openssh_sftp_server PRIVATE
  openssh_libssh
  openssh_openbsd_compat
)

if(WIN32)
  target_include_directories(openssh_sftp_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_sftp_server PRIVATE
    # USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    # _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )
  target_compile_options(openssh_sftp_server PRIVATE
    # /Gy
    # /Qspectre
  )
  target_link_options(openssh_sftp_server PRIVATE
    /entry:wmainCRTStartup
    # /force:multiple
    # /opt:ref
    # /opt:icf
    # /incremental:no
  )
  target_link_libraries(openssh_sftp_server PRIVATE
    openssh_posix_compat
  )
elseif(UNIX)
  target_link_libraries(openssh_sftp_server PRIVATE
    bsd # for freezero()
  )
endif()

# ------------
# openssh_sftp
# ------------

add_executable(openssh_sftp ${openssh_sftp_src})
set_target_properties(openssh_sftp PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
)

target_include_directories(openssh_sftp PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(openssh_sftp PRIVATE
  openssh_libssh
  openssh_openbsd_compat
)

if(WIN32)
  target_include_directories(openssh_sftp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_sftp PRIVATE
    # USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    # _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )
  target_compile_options(openssh_sftp PRIVATE
    # /Gy
    # /Qspectre
  )
  target_link_options(openssh_sftp PRIVATE
    /entry:wmainCRTStartup
    # /force:multiple
    # /opt:ref
    # /opt:icf
    # /incremental:no
  )
  target_link_libraries(openssh_sftp PRIVATE
    openssh_posix_compat
  )
elseif(UNIX)
  target_link_libraries(openssh_sftp PRIVATE
    bsd # for freezero()
  )
endif()

# ---------------
# openssh_ssh_add
# ---------------

add_executable(openssh_ssh_add ${openssh_ssh_add_src})
set_target_properties(openssh_ssh_add PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
)

target_include_directories(openssh_ssh_add PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(openssh_ssh_add PRIVATE
  openssh_libssh
  openssh_openbsd_compat
)

if(WIN32)
  target_include_directories(openssh_ssh_add PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_ssh_add PRIVATE
    # USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    # _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )
  target_compile_options(openssh_ssh_add PRIVATE
    # /Gy
    # /Qspectre
  )
  target_link_options(openssh_ssh_add PRIVATE
    /entry:wmainCRTStartup
    # /force:multiple
    # /opt:ref
    # /opt:icf
    # /incremental:no
  )
  target_link_libraries(openssh_ssh_add PRIVATE
    openssh_posix_compat
  )
elseif(UNIX)
  target_link_libraries(openssh_ssh_add PRIVATE
    bsd # for freezero()
  )
endif()

# -----------------
# openssh_ssh_agent
# -----------------

add_executable(openssh_ssh_agent ${openssh_ssh_agent_src})
set_target_properties(openssh_ssh_agent PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
)

target_include_directories(openssh_ssh_agent PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(openssh_ssh_agent PRIVATE
  openssh_libssh
  openssh_openbsd_compat
)

if(WIN32)
  target_include_directories(openssh_ssh_agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_ssh_agent PRIVATE
    # USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )
  target_compile_options(openssh_ssh_agent PRIVATE
    # /Gy
    # /Qspectre
  )
  target_link_options(openssh_ssh_agent PRIVATE
    /entry:wmainCRTStartup
    # /force:multiple
    # /opt:ref
    # /opt:icf
    # /incremental:no
  )
  target_link_libraries(openssh_ssh_agent PRIVATE
    openssh_posix_compat
  )
elseif(UNIX)
  target_link_libraries(openssh_ssh_agent PRIVATE
    bsd # for freezero()
  )
endif()

# -------------------
# openssh_ssh_keyscan
# -------------------

add_executable(openssh_ssh_keyscan ${openssh_ssh_keyscan_src})
set_target_properties(openssh_ssh_keyscan PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
)

target_include_directories(openssh_ssh_keyscan PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(openssh_ssh_keyscan PRIVATE
  openssh_libssh
  openssh_openbsd_compat
)

if(WIN32)
  target_include_directories(openssh_ssh_keyscan PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_ssh_keyscan PRIVATE
    # USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )
  target_compile_options(openssh_ssh_keyscan PRIVATE
    # /Gy
    # /Qspectre
  )
  target_link_options(openssh_ssh_keyscan PRIVATE
    /entry:wmainCRTStartup
    # /force:multiple
    # /opt:ref
    # /opt:icf
    # /incremental:no
  )
  target_link_libraries(openssh_ssh_keyscan PRIVATE
    openssh_posix_compat
  )
elseif(UNIX)
  target_link_libraries(openssh_ssh_keyscan PRIVATE
    bsd # for freezero()
  )
endif()

# -------------------------
# openssh_ssh_pkcs11_helper
# -------------------------

add_executable(openssh_ssh_pkcs11_helper ${openssh_ssh_pkcs11_helper_src})
set_target_properties(openssh_ssh_pkcs11_helper PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
)

target_include_directories(openssh_ssh_pkcs11_helper PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(openssh_ssh_pkcs11_helper PRIVATE
  openssh_libssh
  openssh_openbsd_compat
)

if(WIN32)
  target_include_directories(openssh_ssh_pkcs11_helper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_ssh_pkcs11_helper PRIVATE
    # USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )
  target_compile_options(openssh_ssh_pkcs11_helper PRIVATE
    # /Gy
    # /Qspectre
  )
  target_link_options(openssh_ssh_pkcs11_helper PRIVATE
    /entry:wmainCRTStartup
    # /force:multiple
    # /opt:ref
    # /opt:icf
    # /incremental:no
  )
  target_link_libraries(openssh_ssh_pkcs11_helper PRIVATE
    openssh_posix_compat
  )
elseif(UNIX)
  target_link_libraries(openssh_ssh_pkcs11_helper PRIVATE
    bsd # for freezero()
  )
endif()

# ---------------------
# openssh_ssh_shellhost
# ---------------------

if(WIN32)
  add_executable(openssh_ssh_shellhost ${openssh_ssh_shellhost_src})
  set_target_properties(openssh_ssh_shellhost PROPERTIES
    LANGUAGE "C"
    LINKER_LANGUAGE "C"
  )

  target_include_directories(openssh_ssh_shellhost PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )

  target_compile_definitions(openssh_ssh_shellhost PRIVATE
    # USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )

  target_compile_options(openssh_ssh_shellhost PRIVATE
    # /Gy
    # /Qspectre
  )

  target_link_options(openssh_ssh_shellhost PRIVATE
    /entry:wmainCRTStartup
    # /force:multiple
    # /opt:ref
    # /opt:icf
    # /incremental:no
  )

  target_link_libraries(openssh_ssh_shellhost PRIVATE
    openssh_libssh
    openssh_openbsd_compat
    openssh_posix_compat
  )
endif()

# ---------------------
# openssh_ssh_sk_helper
# ---------------------

add_executable(openssh_ssh_sk_helper ${openssh_ssh_sk_helper_src})
add_dependencies(openssh_ssh_sk_helper libfido2)
set_target_properties(openssh_ssh_sk_helper PROPERTIES
  LANGUAGE "C"
  LINKER_LANGUAGE "C"
)

target_include_directories(openssh_ssh_sk_helper PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${libfido2_include_dir}
)

target_link_libraries(openssh_ssh_sk_helper PRIVATE
  ${libfido2_static}
  ${libcbor_static}
  openssh_libssh
  openssh_openbsd_compat
)

if(WIN32)
  target_include_directories(openssh_ssh_sk_helper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/contrib/win32/win32compat/inc
  )
  target_compile_definitions(openssh_ssh_sk_helper PRIVATE
    # USE_MSCNG
    WIN32
    _WIN32_WINNT=0x601
    _LIB
    _MBCS
    _CONSOLE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_DECLARE_NONSTDC_NAMES=0
    _WINSOCK_DEPRECATED_NO_WARNINGS
  )
  target_compile_options(openssh_ssh_sk_helper PRIVATE
    # /Gy
    # /Qspectre
  )
  target_link_options(openssh_ssh_sk_helper PRIVATE
    /entry:wmainCRTStartup
    /force:multiple
    /opt:ref
    /opt:icf
    /incremental:no
  )
  target_link_libraries(openssh_ssh_sk_helper PRIVATE
    openssh_posix_compat
    hid.lib
    setupapi.lib
  )
elseif(UNIX)
  target_link_libraries(openssh_ssh_sk_helper PRIVATE
    bsd # for freezero()
  )
endif()
