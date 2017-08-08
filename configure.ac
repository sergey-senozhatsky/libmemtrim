AC_PREREQ([2.65])

AC_INIT([mtrim],[1.0.0])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([config/m4])
AC_CONFIG_AUX_DIR([config/autoconf])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

case "${host_os}" in
	linux-gnu*) HOST_OS="linux-gnu" ;;
	linux-uclibc*) HOST_OS="linux-gnu" ;;
	*)		AC_MSG_ERROR([unkown host-os ${host_os}]) ;;
esac
AC_SUBST(HOST_OS)

case "${host_cpu}" in
	arm*|sa110)		HOST_CPU="arm" ;;
	i?86|x86_64)	HOST_CPU="x86" ;;
	*)			HOST_CPU="${host_cpu}" ;;
esac
AC_SUBST(HOST_CPU)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
LT_INIT
# libtool-2:  LT_INIT()
AM_INIT_AUTOMAKE([foreign no-exeext dist-bzip2])
AM_MAINTAINER_MODE

AC_CHECK_FUNCS([ \
		malloc_trim \
		mallinfo \
		free \
		cfree \
		munmap \
		gettimeofday \
		])

AC_CHECK_LIB([dl], [dlopen], [libdl_LIBS=-ldl],
	     [AC_MSG_ERROR([Couldn't find or use libdl.])])
AC_DEFINE([HAVE_LIBDL], [1], [we have libdl])
AC_SUBST(libdl_LIBS)
AC_SUBST(libdl_LD_LIBRARY_PATH)

AC_CHECK_LIB([pthread], [pthread_rwlock_init], [libpthread_LIBS=-lpthread],
	     [AC_MSG_ERROR([Couldn't find or use libpthread.])])
AC_DEFINE([HAVE_LIBPTHREAD], [1], [we have libpthread])
AC_SUBST(libpthread_LIBS)
AC_SUBST(libpthread_LD_LIBRARY_PATH)

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)
AC_SUBST(libunwind_LD_LIBRARY_PATH)

AC_CONFIG_FILES([
		 Makefile
		 ])
AC_OUTPUT
