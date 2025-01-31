// --------------------- 通用防御模块 ---------------------
const ANDROID_VERSION = 14;
const IS_ARM64 = Process.arch === 'arm64';
let LINKER_BASE = null;

// 动态适配Android 14的linker结构
function initLinkerOffsets() {
    const linker = Process.getModuleByName(IS_ARM64 ? "linker64" : "linker");
    LINKER_BASE = linker.base;
    
    // 动态特征搜索（适配不同ROM）
    const solist_pattern = IS_ARM64 ? 
        "F0 4F 2D E9 1C B0 8D E2" : 
        "2D E9 F0 4F 8D E2 1C B0";
    const result = Memory.scanSync(linker.base, linker.size, solist_pattern);
    
    if (result.length > 0) {
        return {
            solist: result[0].address.add(IS_ARM64 ? 0x38 : 0x28),
            g_module_counter: result[0].address.add(IS_ARM64 ? 0x218 : 0x1C0)
        };
    }
    throw new Error("Unsupported Android version");
}

const linker_offsets = initLinkerOffsets();

// --------------------- Zygote注入对抗模块 ---------------------
// 高级solist链表操作
function hijackSolist() {
    const solist_head = linker_offsets.solist;
    const solist_next_offset = IS_ARM64 ? 0x38 : 0x28;

    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter(args) {
            this.original = solist_head.readPointer();
        },
        onLeave(retval) {
            const current = solist_head.readPointer();
            let prev = current;
            
            while (!prev.isNull()) {
                const next = prev.add(solist_next_offset).readPointer();
                const path_ptr = prev.add(IS_ARM64 ? 0x1A8 : 0x174);
                const path = path_ptr.readPointer().readCString();
                
                if (path && path.includes("frida")) {
                    const fake_next = Memory.alloc(Process.pointerSize);
                    fake_next.writePointer(next);
                    prev.add(solist_next_offset).writePointer(fake_next);
                    Memory.protect(fake_next, Process.pageSize, 'rw-');
                }
                prev = next;
            }
        }
    });
}

// 增强版maps文件过滤
function filterProcMaps() {
    const openat = Module.findExportByName(null, "openat");
    Interceptor.attach(openat, {
        onEnter(args) {
            const path = Memory.readCString(args[1]);
            if (path.includes("/proc/self/maps")) {
                this.fake_fd = _open("/dev/random", 0);
                args[0] = ptr(-1);
            }
        },
        onLeave(retval) {
            if (this.fake_fd) retval.replace(ptr(this.fake_fd));
        }
    });

    const read = Module.findExportByName(null, "read");
    Interceptor.attach(read, {
        onEnter(args) {
            if (this.fake_fd && args[0].toInt32() === this.fake_fd) {
                const buf = Memory.alloc(4096);
                const cleanMaps = Process.enumerateRanges('r-x')
                    .filter(r => !r.file || !r.file.path.includes("frida"))
                    .map(r => `${r.base}-${r.base.add(r.size)} ${r.prot} ${r.file ? r.file.path : ''}`)
                    .join("\n");
                buf.writeUtf8String(cleanMaps);
                args[1] = buf;
                args[2] = ptr(cleanMaps.length);
            }
        }
    });
}

// --------------------- CRC校验对抗模块 ---------------------
const ELF_ORIGINAL_DATA = new Map();
function cacheOriginalLibs() {
    const criticalLibs = [
        "/apex/com.android.runtime/lib64/bionic/libc.so",
        "/apex/com.android.runtime/lib64/bionic/libart.so"
    ];

    criticalLibs.forEach(path => {
        const file = new File(path, "rb");
        ELF_ORIGINAL_DATA.set(path, file.read(file.size));
        file.close();
    });
}

function bypassCRCCheck() {
    const mprotect = Module.findExportByName(null, "mprotect");
    Interceptor.attach(mprotect, {
        onLeave(retval) {
            retval.replace(0); // 强制返回成功
        }
    });

    const checksum = DebugSymbol.getFunctionByName("checksum");
    Interceptor.attach(checksum, {
        onEnter(args) {
            this.buf = args[0];
            this.size = args[1];
        },
        onLeave(retval) {
            const module = Process.findModuleByAddress(this.buf);
            if (module && ELF_ORIGINAL_DATA.has(module.path)) {
                const origCrc = computeCRC(ELF_ORIGINAL_DATA.get(module.path));
                retval.replace(origCrc);
            }
        }
    });

    function computeCRC(data) {
        // 实现与Rust一致的CRC16算法
        let crc = 0x0;
        for (let byte of data) {
            let x = ((crc >> 8) ^ byte) & 255;
            x ^= x >> 4;
            crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x;
        }
        return crc & 0xFFFF;
    }
}

// --------------------- Android 14专项适配 ---------------------
if (ANDROID_VERSION >= 14) {
    // 绕过CFI保护
    const dlopen_ext = Module.findExportByName("linker64", "__loader_dlopen_ext");
    Interceptor.attach(dlopen_ext, {
        onEnter(args) {
            this.name = Memory.readCString(args[0]);
        },
        onLeave(retval) {
            if (this.name.includes("frida")) {
                Memory.protect(retval, Process.pageSize, 'rwx');
                retval.writeU32(0xD503201F); // NOP指令
            }
        }
    });

    // PAC指针签名绕过
    const pac_sign = Module.findExportByName("libpac.so", "pac_sign");
    if (pac_sign) {
        Interceptor.replace(pac_sign, new NativeCallback(() => {
            return ptr(0);
        }, 'pointer', []));
    }
}

// --------------------- 初始化执行 ---------------------
cacheOriginalLibs();
hijackSolist();
filterProcMaps();
bypassCRCCheck();

// 线程伪装（关键！）
Thread.enumerate().forEach(thread => {
    if (thread.context.pc.toString().includes("frida")) {
        const newName = "system_server";
        Thread.updateContext(thread.id, {
            x1: Memory.allocUtf8String(newName).address
        });
    }
});

// 内存混淆（防特征扫描）
Memory.scramble(Module.findBaseAddress("libfrida-gum.so"), 
    Module.findExportByName("libfrida-gum.so", "gum_init"));