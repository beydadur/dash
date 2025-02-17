#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const char ____versions[]
__used __section("__versions") =
	"\x14\x00\x00\x00\x18\x51\xcb\x58"
	"proc_create\0"
	"\x10\x00\x00\x00\x7e\x3a\x2c\x12"
	"_printk\0"
	"\x14\x00\x00\x00\xf6\xce\x86\x7f"
	"single_open\0"
	"\x1c\x00\x00\x00\x81\xf7\x6c\x8e"
	"remove_proc_entry\0\0\0"
	"\x14\x00\x00\x00\x1b\x3b\x35\x30"
	"seq_printf\0\0"
	"\x18\x00\x00\x00\x49\xf7\x1e\x4c"
	"find_get_pid\0\0\0\0"
	"\x14\x00\x00\x00\x18\x91\x26\x24"
	"pid_task\0\0\0\0"
	"\x14\x00\x00\x00\x85\x93\xa9\x22"
	"seq_read\0\0\0\0"
	"\x14\x00\x00\x00\x0b\x1e\xcb\xdc"
	"seq_lseek\0\0\0"
	"\x18\x00\x00\x00\xb6\x8c\x2e\x38"
	"single_release\0\0"
	"\x18\x00\x00\x00\x5e\x99\x8b\x58"
	"param_ops_int\0\0\0"
	"\x18\x00\x00\x00\x0e\x1e\x89\xec"
	"module_layout\0\0\0"
	"\x00\x00\x00\x00\x00\x00\x00\x00";

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "3C6D2AE0B5B26A666CD1F69");
