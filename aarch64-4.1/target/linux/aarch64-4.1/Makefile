#
# Copyright (C) 2011-2015 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

ARCH:=aarch64
BOARD:=aarch64-4.1
BOARDNAME:=Entware (aarch64,kernel-4.1)
FEATURES:=gpio usb audio pci
KERNEL_PATCHVER:=4.1
CPU_TYPE:=cortex-a53
DEFAULT_PACKAGES := toolchain

include $(INCLUDE_DIR)/target.mk

define Target/Description
	Build Software Repository for ARM NASes, like QNAP and Synology.
endef

$(eval $(call BuildTarget))
