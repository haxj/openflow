if BUILD_HW_LIBS

# Options for each platform
if NF2

#
# Build encapsulator as binary
#

bin_PROGRAMS += feature_analyzer/ofanalyzer

feature_analyzer_ofanalyzer_SOURCES = \
	feature_analyzer/encapsulator.c

feature_analyzer_ofanalyzer_LDADD = lib/libopenflow.a $(SSL_LIBS) $(FAULT_LIBS)
feature_analyzer_ofanalyzer_CPPFLAGS = $(AM_CPPFLAGS)

feature_analyzer_ofanalyzer_LDADD += hw-lib/libnf2.a
feature_analyzer_ofanalyzer_CPPFLAGS += -DOF_HW_PLAT -DUSE_NETDEV -g
feature_analyzer_ofanalyzer_CPPFLAGS += -I hw-lib/nf2

noinst_LIBRARIES += hw-lib/libnf2.a
endif

endif
