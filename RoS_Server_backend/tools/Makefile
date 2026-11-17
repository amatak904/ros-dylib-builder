TARGET := iphone:clang:latest:12.0
ARCHS = arm64
GO_EASY_ON_ME = 1

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = RosKenorRedirect
RosKenorRedirect_FILES = RosKenorRedirect.m fishhook.c
RosKenorRedirect_CFLAGS = -Wno-deprecated-declarations
RosKenorRedirect_OBJCFLAGS = -fobjc-arc -Wno-deprecated-declarations
RosKenorRedirect_FRAMEWORKS = Foundation CoreFoundation CoreGraphics UIKit QuartzCore WebKit Security CFNetwork
RosKenorRedirect_INSTALL_PATH = @executable_path/Frameworks
RosKenorRedirect_LDFLAGS = -Wl,-install_name,@executable_path/Frameworks/RosKenorRedirect.dylib

include $(THEOS_MAKE_PATH)/library.mk
