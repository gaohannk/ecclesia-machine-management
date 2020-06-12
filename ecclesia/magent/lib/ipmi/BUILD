# IPMI interface libraries for management agent

licenses(["notice"])

cc_library(
    name = "ipmi",
    hdrs = ["ipmi.h"],
    visibility = ["//:magent_library_users"],
    deps = ["@com_google_absl//absl/status"],
)

cc_library(
    name = "interface_options",
    srcs = ["interface_options.cc"],
    hdrs = ["interface_options.h"],
    visibility = ["//:magent_library_users"],
    deps = [
        "@com_google_absl//absl/flags:flag",
    ],
)

cc_library(
    name = "ipmitool",
    srcs = [
        "ipmitool.cc",
    ],
    hdrs = [
        "ipmitool.h",
    ],
    visibility = ["//:magent_library_users"],
    deps = [
        ":interface_options",
        ":ipmi",
        "//magent/lib/fru:ipmi_fru",
        "//third_party/ipmitool:ipmi",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)
