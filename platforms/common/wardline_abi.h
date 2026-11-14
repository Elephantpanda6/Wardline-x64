#ifndef WARDLINE_ABI_H
#define WARDLINE_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WARDLINE_ABI_VERSION 1u

typedef enum WlArch {
    WL_ARCH_UNKNOWN = 0,
    WL_ARCH_X64     = 1,
    WL_ARCH_ARM64   = 2
} WlArch;

typedef enum WlIsolationLevel {
    WL_ISOLATION_L0_RESTRICTED_JOB = 0,
    WL_ISOLATION_L1_APPCONTAINER   = 1,
    WL_ISOLATION_L2_MICROVM        = 2
} WlIsolationLevel;

typedef enum WlPeClass {
    WL_PE_UNKNOWN       = 0,
    WL_PE_AMD64         = 1,
    WL_PE_ARM64         = 2,
    WL_PE_ARM64EC       = 3,
    WL_PE_X86           = 4,
    WL_PE_SCRIPT_OR_RAW = 5
} WlPeClass;

typedef enum WlStatusCode {
    WL_OK                        = 0,
    WL_ERR_INVALID_ARG           = 1,
    WL_ERR_NOT_SUPPORTED_ARCH    = 2,
    WL_ERR_PE_INVALID            = 3,
    WL_ERR_PE_DISALLOWED_ARCH    = 4,
    WL_ERR_PRISM_BLOCKED         = 5,
    WL_ERR_JOB_CREATION          = 6,
    WL_ERR_TOKEN_RESTRICTION     = 7,
    WL_ERR_APPCONTAINER          = 8,
    WL_ERR_SPAWN                 = 9,
    WL_ERR_TIMEOUT_KILLED        = 10,
    WL_ERR_PIPE                  = 11,
    WL_ERR_ACL                   = 12,
    WL_ERR_PROBE                 = 13,
    WL_ERR_MEMORY_LIMIT          = 14,
    WL_ERR_IO                    = 15
} WlStatusCode;

typedef struct WlHostCapabilities {
    uint32_t arch;
    uint32_t abi_version;
    uint8_t  is_wow64_emulated;
    uint8_t  cet_shadow_stack_supported;
    uint8_t  pac_bti_available;
    uint8_t  hyperv_hcs_available;
    uint8_t  appcontainer_supported;
    uint8_t  job_object_iocp_supported;
    uint8_t  reserved[2];
    uint32_t os_build_number;
    uint32_t page_size;
} WlHostCapabilities;

typedef struct WlSpawnRequest {
    const uint8_t* executable_utf8;
    size_t         executable_len;
    const uint8_t* cmdline_utf8;
    size_t         cmdline_len;
    const uint8_t* working_dir_utf8;
    size_t         working_dir_len;
    const uint8_t* env_block_utf8;
    size_t         env_block_len;
    const uint8_t* container_name_utf8;
    size_t         container_name_len;
    const uint8_t* rw_paths_utf8;
    size_t         rw_paths_len;
    const uint8_t* ro_paths_utf8;
    size_t         ro_paths_len;
    uint32_t       isolation_level;
    uint32_t       timeout_ms;
    uint64_t       max_memory_bytes;
    uint32_t       max_processes;
    uint32_t       cpu_rate_percent;
    uint8_t        allow_prism_x64;
    uint8_t        allow_arm64ec;
    uint8_t        enable_acg;
    uint8_t        enable_cet;
    uint8_t        capture_output;
    uint8_t        reserved[3];
} WlSpawnRequest;

typedef struct WlIoBuffers {
    uint8_t* stdout_ptr;
    size_t   stdout_cap;
    uint8_t* stderr_ptr;
    size_t   stderr_cap;
    uint8_t* detail_ptr;
    size_t   detail_cap;
} WlIoBuffers;

typedef struct WlSpawnResult {
    uint32_t status_code;
    uint32_t win32_error;
    uint32_t exit_code;
    uint8_t  timed_out;
    uint8_t  oom_killed;
    uint8_t  emulation_detected;
    uint8_t  acg_applied;
    uint32_t pid;
    uint64_t peak_memory_bytes;
    uint64_t cpu_time_us;
    size_t   stdout_len;
    size_t   stderr_len;
    size_t   detail_len;
} WlSpawnResult;

uint32_t wl_engine_abi_version(void);
uint32_t wl_engine_arch(void);
uint32_t wl_probe_capabilities(WlHostCapabilities* out_caps);
uint32_t wl_classify_pe(const uint8_t* bytes_ptr, size_t bytes_len);
uint32_t wl_spawn_isolated(
    const WlSpawnRequest* req,
    WlIoBuffers* io,
    WlSpawnResult* res
);
uint32_t wl_create_hardened_pipe(
    const uint8_t* name_utf8,
    size_t name_len,
    size_t* out_handle,
    uint32_t* out_win32_err
);
uint32_t wl_set_owner_only_dacl_utf8(
    const uint8_t* path_utf8,
    size_t path_len,
    uint8_t is_dir,
    uint32_t* out_win32_err
);
uint32_t wl_harden_current_process_dacl(uint32_t* out_win32_err);

#ifdef __cplusplus
}
#endif

#endif
