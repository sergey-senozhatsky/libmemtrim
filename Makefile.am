ACLOCAL_AMFLAGS = -I config/m4

SUBDIRS = .

lib_LTLIBRARIES = \
	libmtrim.la

libmtrim_la_LDFLAGS = -version-info 1:0:0

libmtrim_la_SOURCES = libmtrim.c

libmtrim_la_LIBADD = \
	$(libsupcxx_LIBS) \
	$(libstdcxx_LIBS) \
	$(libdl_LIBS)
