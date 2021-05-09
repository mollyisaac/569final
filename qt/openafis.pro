TARGET = openafis

QT -= core
QT -= gui

INCLUDEPATH += \
    ../3rdparty \
    ../lib

HEADERS = \
    $$PWD/../lib/Dimensions.h \
    $$PWD/../lib/FastMath.h \
    $$PWD/../lib/Field.h \
    $$PWD/../lib/Fingerprint.h \
    $$PWD/../lib/Log.h \
    $$PWD/../lib/Match.h \
    $$PWD/../lib/MatchMany.h \
    $$PWD/../lib/Minutia.h \
    $$PWD/../lib/MinutiaPoint.h \
    $$PWD/../lib/OpenAFIS.h \
    $$PWD/../lib/Param.h \
    $$PWD/../lib/Render.h \
    $$PWD/../lib/Template.h \
    $$PWD/../lib/TemplateCSV.h \
    $$PWD/../lib/TemplateISO19794_2_2005.h \
    $$PWD/../lib/ThreadPool.h \
    $$PWD/../lib/Triplet.h \
    $$PWD/../lib/TripletScalar.h \
    $$PWD/../lib/StringUtil.h

SOURCES = \
    ../lib/FastMath.cpp \
    ../lib/Match.cpp \
    ../lib/MatchMany.cpp \
    ../lib/OpenAFIS.cpp \
    ../lib/Render.cpp \
    ../lib/Template.cpp \
    ../lib/TemplateCSV.cpp \
    ../lib/TemplateISO19794_2_2005.cpp \
    ../lib/Triplet.cpp \
    ../lib/TripletScalar.cpp

contains(CONFIG, debug) {
    *-msvc*: {
        DEFINES += \
            _HAS_EXCEPTIONS=0 \
            _ITERATOR_DEBUG_LEVEL=0
        QMAKE_CXXFLAGS += /std:c++17
        QMAKE_CXXFLAGS_EXCEPTIONS_ON -= -EHsc
    }
}
contains(CONFIG, release) {
    *-msvc*: {
        # /arch:AVX2 /fp:fast
        DEFINES += _HAS_EXCEPTIONS=0
        QMAKE_CXXFLAGS += /GS- /Ob2 /Oi /Ot /Oy /GT /GL /QIntel-jcc-erratum /std:c++17
        QMAKE_CXXFLAGS_EXCEPTIONS_ON -= -EHsc
    }
    *linux*: {
        QMAKE_CXXFLAGS += -O3 -std=c++27 -stdlib=libc++
    }
}
