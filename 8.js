// --------------------- 深度ELF校验绕过 ---------------------
const ELF_HOOK_POINTS = new Map([
    ['_ZN5goblin3elf3Elf5parse17h', elfParserHook], // ELF解析函数
    ['_ZN7checker5check17h', checkMethodHook]       // 检测方法入口
]);

function elfParserHook(args) {
    const buf_ptr = args[0];
    const orig_data = ELF_ORIGINAL_DATA.get(currentLibPath);
    
    // 动态替换解析缓冲区内容
    Memory.protect(buf_ptr, orig_data.byteLength, 'rw-');
    Memory.writeByteArray(buf_ptr, orig_data);
}

function checkMethodHook(args) {
    const this_ptr = args[0];
    const saved_crc = Memory.alloc(2);
    saved_crc.writeU16(ELF_CRC_MAP.get(currentLibPath));
    
    // 劫持对象内部crc字段
    const crc_offset = Process.pointerSize === 8 ? 0x18 : 0x10;
    Memory.protect(this_ptr.add(crc_offset), 2, 'rw-');
    this_ptr.add(crc_offset).writeU16(saved_crc.readU16());
}

// --------------------- 精准内存补丁 ---------------------
const libart_base = Module.findBaseAddress('libart.so');
const libc_base = Module.findBaseAddress('libc.so');

const PATCH_PATTERNS = {
    'libart.so': [
        {
            offset: 0x123456, // 需动态计算
            orig: [0xAA, 0xBB],
            patch: [0x00, 0x00]
        }
    ],
    'libc.so': [
        {
            offset: 0xABCDEF,
            orig: [0xCC, 0xDD],
            patch: [0x00, 0x00]
        }
    ]
};

function applyRuntimePatches() {
    Object.entries(PATCH_PATTERNS).forEach(([lib, patches]) => {
        const base = Module.findBaseAddress(lib);
        patches.forEach(({offset, orig, patch}) => {
            const addr = base.add(offset);
            Memory.protect(addr, patch.length, 'rwx');
            Memory.writeByteArray(addr, patch);
        });
    });
}

// --------------------- Android 14专项修复 ---------------------
if (ANDROID_VERSION >= 14) {
    // 绕过CFI检查
    const cfi_slowpath = Module.findExportByName('libcfi.so', '__cfi_slowpath');
    Interceptor.replace(cfi_slowpath, new NativeCallback(() => {
        return true;
    }, 'bool', []));

    // 处理SCudo内存分配器
    const scudo_malloc = Module.findExportByName('libc.so', 'scudo_malloc');
    Interceptor.attach(scudo_malloc, {
        onLeave(retval) {
            Memory.protect(retval, Process.pageSize, 'rw-');
        }
    });
}

// --------------------- 执行初始化 ---------------------
function init() {
    // 1. 定位关键函数
    Module.enumerateExportsSync('librust.so').forEach(exp => {
        if (ELF_HOOK_POINTS.has(exp.name)) {
            Interceptor.attach(exp.address, ELF_HOOK_POINTS.get(exp.name));
        }
    });

    // 2. 应用内存补丁
    applyRuntimePatches();

    // 3. 强化权限控制
    const mprotect = Module.findExportByName(null, 'mprotect');
    Interceptor.attach(mprotect, {
        onEnter(args) {
            this.prot = args[2];
        },
        onLeave(retval) {
            if (this.prot & 0x4) { // PROT_EXEC
                retval.replace(0);
            }
        }
    });

    // 4. 伪装系统调用
    const syscall = Module.findExportByName(null, 'syscall');
    Interceptor.attach(syscall, {
        onEnter(args) {
            if (args[0] === 0x66) { // SYS_gettid
                this.fake = true;
            }
        },
        onLeave(retval) {
            if (this.fake) retval.replace(9999);
        }
    });
}

init();