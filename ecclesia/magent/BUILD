licenses(["notice"])

cc_binary(
    name = "magent_indus",
    srcs = ["main_indus.cc"],
    visibility = ["//:magent_library_users"],
    deps = [
        ":magent_hdr",
        "//lib/apifs",
        "//lib/io:ioctl",
        "//lib/smbios:reader",
        "//lib/types:fixed_range_int",
        "//magent/lib/eeprom",
        "//magent/lib/io:pci_sys",
        "//magent/lib/io:smbus",
        "//magent/lib/io:smbus_kernel_dev",
        "//magent/lib/ipmi:ipmitool",
        "//magent/redfish/indus",
        "//magent/sysmodel/x86:x86_sysmodel",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@com_google_tensorflow_serving//tensorflow_serving/util/net_http/server/public:http_server_api",
    ],
)

cc_library(
    name = "magent_hdr",
    hdrs = ["main_common.h"],
    deps = [
        "//magent/lib/thread_pool",
        "@com_google_tensorflow_serving//tensorflow_serving/util/net_http/server/public:http_server",
        "@com_google_tensorflow_serving//tensorflow_serving/util/net_http/server/public:http_server_api",
    ],
)
