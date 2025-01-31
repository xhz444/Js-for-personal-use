// --------------------- 深度ELF校验增强绕过 ---------------------
const ELF_HOOK_POINTS = new Map([
    ['_ZN5goblin3elf3Elf5parse17h', elfParserHook], 
    ['_ZN7checker5check17h', checkMethodHook],
    ['_ZN4core3ops8function6FnOnce9call_once17h', rustClosureHook] // 新增闭包处理
]);

// 新增：拦截Rust闭包执行
function rustClosureHook(args) {
    const callback_ptr = args[0];
    const orig_callback = Memory.readPointer(callback_ptr);
    
    Interceptor.replace(orig_callback, new NativeCallback(() => {
        return 0; // 强制返回成功
    }, 'i64', []));
}

// 增强ELF解析拦截
function elfParserHook(args) {
    const buf_ptr = args[0];
    const currentLibPath = getCurrentLibPath(buf_ptr); // 动态获取路径
    
    if (ELF_ORIGINAL_DATA.has(currentLibPath)) {
        const orig_data = ELF_ORIGINAL_DATA.get(currentLibPath);
        const buf_size = Memory.readU32(buf_ptr.add(Process.pointerSize));
        
        // 精准替换缓冲区内容
        Memory.protect(buf_ptr, orig_data.byteLength + 8, 'rw-');
        Memory.writeU32(buf_ptr.add(Process.pointerSize), orig_data.byteLength);
        Memory.writeByteArray(buf_ptr.add(8), orig_data);
    }
}

// 动态获取当前检测库路径
function getCurrentLibPath(buf_ptr) {
    const stack = Thread.backtrace(this.context, Backtracer.ACCURATE);
    for (let addr of stack) {
        const mod = Process.findModuleByAddress(addr);
        if (mod && mod.path.includes("librust.so")) {
            const disasm = Instruction.parse(addr);
            if (disasm.operation === 'BL' || disasm.operation === 'BLX') {
                const str_ptr = disasm.operands[0].value;
                return Memory.readCString(str_ptr);
            }
        }
    }
    return '';
}

// --------------------- 动态内存补丁系统 ---------------------
function generateRuntimePatches() {
    const PATCH_PATTERNS = {
        'libart.so': {
            // 定位特征码：mov w0, #0x1; ret
            signature: '20 00 80 52 C0 03 5F D6',
            replacement: [0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6] // mov w0, #0x0
        },
        'libc.so': {
            signature: '09 00 80 52 C0 03 5F D6',
            replacement: [0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6]
        }
    };

    Object.entries(PATCH_PATTERNS).forEach(([lib, cfg]) => {
        const base = Module.findBaseAddress(APEX_PATHS[lib]);
        if (!base) return;

        const result = Memory.scanSync(base, 0x1000000, cfg.signature);
        result.forEach(match => {
            Memory.protect(match.address, cfg.replacement.length, 'rwx');
            Memory.writeByteArray(match.address, cfg.replacement);
        });
    });
}

// Android 14 APEX路径映射
const APEX_PATHS = {
    'libart.so': '/apex/com.android.art/lib64/libart.so',
    'libc.so': '/apex/com.android.runtime/lib64/bionic/libc.so'
};

// --------------------- Android 14深度防护 ---------------------
function bypassAdvancedProtection() {
    // 1. 绕过CFI强化检查
    const cfi_slowpath = Module.findExportByName('libcfi.so', '__cfi_slowpath');
    if (cfi_slowpath) {
        Interceptor.replace(cfi_slowpath, new NativeCallback(() => {
            return true;
        }, 'bool', []));
    }

    // 2. 禁用SELinux execmem检测
    const selinux = Module.findExportByName('libselinux.so', 'avc_has_perm');
    Interceptor.attach(selinux, {
        onEnter(args) {
            const perm = Memory.readCString(args[4]);
            if (perm === 'execmem') {
                args[4] = Memory.allocUtf8String('null').address;
            }
        }
    });

    // 3. 处理SCudo内存隔离
    const malloc_usable_size = Module.findExportByName('libc.so', 'malloc_usable_size');
    Interceptor.attach(malloc_usable_size, {
        onLeave(retval) {
            Memory.protect(retval, retval.toInt32(), 'rw-');
        }
    });
}

// --------------------- 初始化执行 ---------------------
function init() {
    // 0. 环境检测
    if (Process.arch !== 'arm64') throw new Error("仅支持ARM64架构");
    
    // 1. 路径重定向（关键！）
    ELF_ORIGINAL_DATA.forEach((_, lib) => {
        const fakePath = `/data/local/tmp/${lib}`;
        const origPath = APEX_PATHS[lib];
        if (!File.exists(fakePath)) File.copy(origPath, fakePath);
    });

    // 2. 动态补丁
    generateRuntimePatches();

    // 3. 强化Hook
    Module.enumerateExportsSync('librust.so').forEach(exp => {
        if (ELF_HOOK_POINTS.has(exp.name.substring(0, 15))) { // 处理Rust名称修饰
            Interceptor.attach(exp.address, ELF_HOOK_POINTS.get(exp.name.substring(0,15)));
        }
    });

    // 4. Android 14专项处理
    if (ANDROID_VERSION >= 14) {
        bypassAdvancedProtection();
        
        // 内核级隐藏（需root）
        const syscall_openat = Module.findExportByName(null, 'syscall');
        Interceptor.attach(syscall_openat, {
            onEnter(args) {
                if (args[0] === 56) { // SYS_openat
                    const path = Memory.readCString(args[2]);
                    if (path.includes('librust.so')) {
                        args[2] = Memory.allocUtf8String('/dev/null').address;
                    }
                }
            }
        });
    }
}

// --------------------- 执行入口 ---------------------
Java.perform(() => {
    init();
    Thread.sleep(500); // 等待环境初始化
});