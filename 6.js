'use strict';

// 动态获取新版 linker 结构偏移
function getLinkerOffsets() {
    const linker = Process.getModuleByName("linker64");

    // 方法1：特征扫描
    const solist_pattern = "7F 45 4C 46 02 01 01 ?? ?? ?? ?? ?? ?? ?? ?? ??";
    const scanner = Memory.scanSync(linker.base, linker.size, solist_pattern);
    if (scanner.length > 0) {
        return {
            solist: scanner[0].address.add(0x30),
            somain: scanner[0].address.add(0x48),
            g_module_counter: scanner[0].address.add(0x200)
        };
    }

    // 方法2：解析 __loader_dlopen
    const dlopen_addr = Module.findExportByName("linker64", "__loader_dlopen");
    if (dlopen_addr) {
        let ins = Instruction.parse(dlopen_addr);
        while (ins.next().mnemonic !== 'bl') {} 
        return {
            solist: ins.next().operands[1].value
        };
    }

    throw new Error("Unsupported Android 14 version");
}

const linker_offsets = getLinkerOffsets();

// **增强版 solist 对抗**
const solist_head = linker_offsets.solist;
const solist_next_offset = 0x38;

const fake_node = Memory.alloc(0x200);
fake_node.writeUtf8String("/system/lib64/libutils.so");

Interceptor.attach(Module.findExportByName("linker64", "__loader_android_dlopen_ext"), {
    onEnter(args) {
        this.original_head = solist_head.readPointer();
    },
    onLeave(retval) {
        const current_head = solist_head.readPointer();
        if (!current_head.equals(this.original_head)) {
            const new_node = fake_node;
            new_node.add(solist_next_offset).writePointer(current_head);
            solist_head.writePointer(new_node);
        }
    }
});

// **深度 maps 伪装**
const openat = Module.findExportByName(null, "openat");
const read = Module.findExportByName(null, "read");

Interceptor.attach(openat, {
    onEnter(args) {
        const path = Memory.readCString(args[1]);
        if (path.includes("/proc/self/maps")) {
            this.fake_fd = _open("/dev/random", 0);
            args[0] = ptr(-1);
        }
    },
    onLeave(retval) {
        if (this.fake_fd) {
            retval.replace(ptr(this.fake_fd));
        }
    }
});

Interceptor.attach(read, {
    onEnter(args) {
        if (this.fake_fd && args[0].toInt32() === this.fake_fd) {
            this.buf = Memory.alloc(0x1000);
            this.buf.writeUtf8String(generateFakeMaps());
            args[1] = this.buf;
            args[2] = ptr(0x1000);
        }
    }
});

function generateFakeMaps() {
    let maps = "";
    Process.enumerateRanges('r--').forEach(range => {
        if (!range.file || range.file.path.includes('frida')) {
            maps += `${range.base}-${range.base.add(range.size)} ... [anon]\n`;
        } else {
            maps += `${range.base}-${range.base.add(range.size)} ... ${range.file.path}\n`;
        }
    });
    return maps;
}

// **计数器对抗**
const counter_addr = linker_offsets.g_module_counter;
Memory.protect(counter_addr, 8, 'rw-');
Memory.accessWatch(counter_addr, 8, {
    onAccess: function(details) {
        if (details.operation === 'write') {
            details.address.writeU64(0);
        }
    }
});

// **反检测增强**
// 线程伪装
Interceptor.attach(Module.findExportByName(null, "pthread_create"), {
    onEnter(args) {
        const name_ptr = args[3];
        const orig_name = name_ptr.readCString();
        if (orig_name && orig_name.includes("gum-js-loop")) {
            name_ptr.writeUtf8String("Binder:");
        }
    }
});

// JIT 代码混淆
const jit_alloc = Module.findExportByName("libart.so", "_ZN3artJitCodeCacheAllocate");
Interceptor.attach(jit_alloc, {
    onLeave(retval) {
        Memory.protect(retval, 4096, 'rwx');
        Memory.writeByteArray(retval, [...Array(4096)].map(() => Math.random()*256));
    }
});

// 系统调用混淆
Interceptor.attach(Module.findExportByName(null, "syscall"), {
    onEnter(args) {
        if (args[0].toInt32() === 101 /* gettid */) {
            args[0] = ptr(99999);
        }
    }
});

// **动态适配优化**
function scanLinkerStructure() {
    const linker = Process.getModuleByName("linker64");
    const candidates = Memory.scanSync(linker.base, linker.size, "7F 45 4C 46 02 01 01 ?? ?? ?? ?? ?? ?? ?? ?? ??");

    candidates.forEach(candidate => {
        const potential_solist = candidate.address.add(0x30);
        if (potential_solist.readPointer() != null) {
            return potential_solist;
        }
    });
    throw new Error("Structure not found");
}

// **mprotect 保护绕过**
function bypassMprotect() {
    const mprotect = Module.findExportByName(null, "mprotect");
    Interceptor.attach(mprotect, {
        onEnter(args) {
            if (args[2].toInt32() === (0x1 | 0x2)) {
                this.shouldForce = true;
            }
        },
        onLeave(retval) {
            if (this.shouldForce) {
                retval.replace(ptr(0));
            }
        }
    });
}

// **实时监控检测**
const detector = Process.enumerateModules().find(m => m.name === "libdetector.so");

Stalker.follow({
    events: {
        call: true,
        ret: false
    },
    onReceive: function(events) {
        events.forEach(event => {
            if (event.target.equals(detector.base.add(0x1234))) {
                Thread.backtrace(event.context, Backtracer.ACCURATE)
                    .forEach(frame => {
                        if (frame.moduleName === "libfrida-gum.so") {
                            Memory.protect(frame.returnAddress, 4, 'rwx');
                            frame.returnAddress.writeU32(0xd503201f); // NOP 指令
                        }
                    });
            }
        });
    }
});

// 启动 Hook
bypassMprotect();
console.log("Android 14 Hook 方案已成功注入！");