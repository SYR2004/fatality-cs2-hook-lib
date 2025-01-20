-- SYR1337
assert(ffi, "ffi is invalid, please allow insecure script")
ffi.cdef([[
    typedef struct Thread32Entry {
        uint32_t dwSize;
        uint32_t cntUsage;
        uint32_t th32ThreadID;
        uint32_t th32OwnerProcessID;
        long tpBasePri;
        long tpDeltaPri;
        uint32_t dwFlags;
    } Thread32Entry;
    
    typedef struct {
        uint8_t nRefCount;
    } ShutDownWrapper;
]])

local arrHooks = {}
local arrThreads = {}
local NULLPTR = ffi.cast("void*", 0)
local INVALID_HANDLE = ffi.cast("void*", - 1)
local function CallModuleExport(szModule, szProc, szTypeof, ...)
    local pProcFunction = ffi.cast("void*", utils.find_export(szModule:lower(), szProc))
    if pProcFunction == NULLPTR then
        return nil
    end

    return ffi.cast(szTypeof, pProcFunction)(...)
end

local function Thread(nTheardID)
    local hThread = CallModuleExport("Kernel32.dll", "OpenThread", "void*(__cdecl*)(uint32_t, int, uint32_t)", 0x0002, 0, nTheardID)
    if hThread == NULLPTR or hThread == INVALID_HANDLE then
        return false
    end

    return setmetatable({
        bValid = true,
        nId = nTheardID,
        hThread = hThread,
        bIsSuspended = false
    }, {
        __index = {
            Suspend = function(self)
                if self.bIsSuspended or not self.bValid then
                    return false
                end

                if CallModuleExport("Kernel32.dll", "SuspendThread", "uint32_t(__cdecl*)(void*)", self.hThread) ~= - 1 then
                    self.bIsSuspended = true
                    return true
                end

                return false
            end,

            Resume = function(self)
                if not self.bIsSuspended or not self.bValid then
                    return false
                end

                if CallModuleExport("Kernel32.dll", "ResumeThread", "uint32_t(__cdecl*)(void*)", self.hThread) ~= - 1 then
                    self.bIsSuspended = false
                    return true
                end

                return false
            end,

            Close = function(self)
                if not self.bValid then
                    return
                end

                self:Resume()
                self.bValid = false
                CallModuleExport("Kernel32.dll", "CloseHandle", "int(__cdecl*)(void*)", self.hThread)
            end
        }
    })
end

local function UpdateThreadList()
    arrThreads = {}
    local hSnapShot = CallModuleExport("Kernel32.dll", "CreateToolhelp32Snapshot", "void*(__cdecl*)(uint32_t, uint32_t)", 0x00000004, 0)
    if hSnapShot == INVALID_HANDLE then
        return false
    end

    local pThreadEntry = ffi.new("struct Thread32Entry[1]")
    pThreadEntry[0].dwSize = ffi.sizeof("struct Thread32Entry")
    if CallModuleExport("Kernel32.dll", "Thread32First", "int(__cdecl*)(void*, struct Thread32Entry*)", hSnapShot, pThreadEntry) == 0 then
        CallModuleExport("Kernel32.dll", "CloseHandle", "int(__cdecl*)(void*)", hSnapShot)
        return false
    end

    local nCurrentThreadID = CallModuleExport("Kernel32.dll", "GetCurrentThreadId", "uint32_t(__cdecl*)()")
    local nCurrentProcessID = CallModuleExport("Kernel32.dll", "GetCurrentProcessId", "uint32_t(__cdecl*)()")
    while CallModuleExport("Kernel32.dll", "Thread32Next", "int(__cdecl*)(void*, struct Thread32Entry*)", hSnapShot, pThreadEntry) > 0 do
        if pThreadEntry[0].dwSize >= 20 and pThreadEntry[0].th32OwnerProcessID == nCurrentProcessID and pThreadEntry[0].th32ThreadID ~= nCurrentThreadID then
            local hThread = Thread(pThreadEntry[0].th32ThreadID)
            if not hThread then
                for _, pThread in pairs(arrThreads) do
                    pThread:Close()
                end

                arrThreads = {}
                CallModuleExport("Kernel32.dll", "CloseHandle", "int(__cdecl*)(void*)", hSnapShot)
                return false
            end

            table.insert(arrThreads, hThread)
        end
    end

    CallModuleExport("Kernel32.dll", "CloseHandle", "int(__cdecl*)(void*)", hSnapShot)
    return true
end

local function SuspendThreads()
    if not UpdateThreadList() then
        return false
    end

    for _, hThread in pairs(arrThreads) do
        hThread:Suspend()
    end

    return true
end

local function ResumeThreads()
    for _, hThread in pairs(arrThreads) do
        hThread:Resume()
        hThread:Close()
    end
end

local function CreateInlineHook(pTarget, pDetour, szType)
    assert(type(pDetour) == "function", "hook library error: invalid detour function")
    assert(type(pTarget) == "cdata" or type(pTarget) == "userdata" or type(pTarget) == "number" or type(pTarget) == "function", "hook library error: invalid target function")
    if not SuspendThreads() then
        ResumeThreads()
        print("hook library error: failed suspend threads")
        return false
    end

    local arrBackUp = ffi.new("uint8_t[14]")
    local pTargetFn = ffi.cast(szType, pTarget)
    local pBytes = ffi.cast("uint8_t*", pTargetFn)
    local arrShellCode = ffi.new("uint8_t[14]", {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    })

    if pBytes[0] == 0xE9 or (pBytes[0] == 0xFF and pBytes[1] == 0x25) then
        print(("warning: %p already hooked, rehook this function"):format(pTarget))
    end

    local __Object = {
        bValid = true,
        bAttached = false,
        pBackup = arrBackUp,
        pTarget = pTargetFn,
        pOldProtect = ffi.new("uint32_t[1]"),
        hCurrentProcess = CallModuleExport("Kernel32.dll", "GetCurrentProcess", "void*(__cdecl*)()")
    }

    ffi.copy(arrBackUp, pTargetFn, ffi.sizeof(arrBackUp))
    ffi.cast("uintptr_t*", arrShellCode + 0x6)[0] = ffi.cast("uintptr_t", ffi.cast(szType, function(...)
        local bSuccessfully, pResult = pcall(pDetour, __Object, ...)
        if not bSuccessfully then
            __Object:Remove()
            print(("[hook library]: unexception runtime error -> %s"):format(pResult))
            return pTargetFn(...)
        end

        return pResult
    end))

    __Object.__index = setmetatable(__Object, {
        __call = function(self, ...)
            if not self.bValid then
                return nil
            end

            self:Detach()
            local bSuccessfully, pResult = pcall(self.pTarget, ...)
            if not bSuccessfully then
                self.bValid = false
                print(("[hook library]: runtime error -> %s"):format(pResult))
                return nil
            end

            self:Attach()
            return pResult
        end,

        __index = {
            Attach = function(self)
                if self.bAttached or not self.bValid then
                    return false
                end

                self.bAttached = true
                CallModuleExport("Kernel32.dll", "VirtualProtect", "int(__cdecl*)(void*, uint64_t, uint32_t, uint32_t*)", self.pTarget, ffi.sizeof(arrBackUp), 0x40, self.pOldProtect)
                ffi.copy(self.pTarget, arrShellCode, ffi.sizeof(arrBackUp))
                CallModuleExport("Kernel32.dll", "VirtualProtect", "int(__cdecl*)(void*, uint64_t, uint32_t, uint32_t*)", self.pTarget, ffi.sizeof(arrBackUp), self.pOldProtect[0], self.pOldProtect)
                CallModuleExport("Kernel32.dll", "FlushInstructionCache", "int(__cdecl*)(void*, void*, uint64_t)", self.hCurrentProcess, self.pTarget, ffi.sizeof(arrBackUp))
                return true
            end,

            Detach = function(self)
                if not self.bAttached or not self.bValid then
                    return false
                end

                self.bAttached = false
                CallModuleExport("Kernel32.dll", "VirtualProtect", "int(__cdecl*)(void*, uint64_t, uint32_t, uint32_t*)", self.pTarget, ffi.sizeof(arrBackUp), 0x40, self.pOldProtect)
                ffi.copy(self.pTarget, self.pBackup, ffi.sizeof(arrBackUp))
                CallModuleExport("Kernel32.dll", "VirtualProtect", "int(__cdecl*)(void*, uint64_t, uint32_t, uint32_t*)", self.pTarget, ffi.sizeof(arrBackUp), self.pOldProtect[0], self.pOldProtect)
                CallModuleExport("Kernel32.dll", "FlushInstructionCache", "int(__cdecl*)(void*, void*, uint64_t)", self.hCurrentProcess, self.pTarget, ffi.sizeof(arrBackUp))
                return true
            end,

            Remove = function(self)
                if not self.bValid then
                    return false
                end

                SuspendThreads()
                self:Detach()
                ResumeThreads()
                self.bValid = false
            end
        }
    })

    __Object:Attach()
    table.insert(arrHooks, __Object)
    ResumeThreads()
    return __Object
end

local function CreateVtableHook(pInterface, pDetour, nIndex, szType)
    assert(type(pDetour) == "function", "vtable hook error: invalid detour function")
    assert(type(pInterface) == "cdata" or type(pInterface) == "userdata", "vtable hook error: invalid target function")
     if not SuspendThreads() then
        ResumeThreads()
        print("vtable hook error: failed suspend threads")
        return false
    end

    local nDataSize = ffi.sizeof("void*")
    local pVtable = ffi.cast("void***", pInterface)[0]
    if not pVtable or pVtable == ffi.NULL or pVtable == NULLPTR then
        print("[vtable hook]: invalid vtable")
        return nil
    end

    local __Object = {
        bAttach = false,
        nIndex = nIndex,
        pVtable = pVtable,
        bAvailable = true,
        pCallBackDetourFn = nil,
        pOldProtect = ffi.new("uint32_t[1]"),
        pVtableBase = ffi.cast("uintptr_t", pVtable),
        pTargetOriginalFn = ffi.cast(szType, pVtable[nIndex])
    }

    __Object.pCallBackDetourFn = ffi.cast(szType, function(...)
        local bSuccessfully, pResult = pcall(pDetour, __Object, ...)
        if not bSuccessfully then
            __Object:Remove()
            print(("[vtable hook]: unexception runtime error -> %s"):format(pResult))
            return __Object.pTargetOriginalFn(...)
        end

        return pResult
    end)

    __Object.__index = setmetatable(__Object, {
        __call = function(self, ...)
            if not self.bAvailable or not self.bAttach then
                return nil
            end

            local bSuccessfully, pResult = pcall(self.pTargetOriginalFn, ...)
            if not bSuccessfully then
                self:Detach()
                return nil
            end

            return pResult
        end,

        __index = {
            IsValid = function(this)
                return this.bAvailable
            end,

            Attach = function(self)
                if not self.bAttach and self.bAvailable then
                    self.bAttach = true
                    local pTargetBase = ffi.cast("void*", self.pVtableBase + (nIndex * nDataSize))
                    CallModuleExport("Kernel32.dll", "VirtualProtect", "int(__cdecl*)(void*, uint64_t, uint32_t, uint32_t*)", pTargetBase, nDataSize, 0x40, self.pOldProtect)
                    self.pVtable[nIndex] = ffi.cast("void*", self.pCallBackDetourFn)
                    CallModuleExport("Kernel32.dll", "VirtualProtect", "int(__cdecl*)(void*, uint64_t, uint32_t, uint32_t*)", pTargetBase, nDataSize, self.pOldProtect[0], self.pOldProtect)
                    return true
                end

                return false
            end,

            Detach = function(self)
                if self.bAttach and self.bAvailable then
                    self.bAttach = false
                    local pTargetBase = ffi.cast("void*", self.pVtableBase + (nIndex * nDataSize))
                    CallModuleExport("Kernel32.dll", "VirtualProtect", "int(__cdecl*)(void*, uint64_t, uint32_t, uint32_t*)", pTargetBase, nDataSize, 0x40, self.pOldProtect)
                    self.pVtable[nIndex] = ffi.cast("void*", self.pTargetOriginalFn)
                    CallModuleExport("Kernel32.dll", "VirtualProtect", "int(__cdecl*)(void*, uint64_t, uint32_t, uint32_t*)", pTargetBase, nDataSize, self.pOldProtect[0], self.pOldProtect)
                    return true
                end

                return false
            end,

            Remove = function(this)
                if this.bAvailable then
                    this:Detach()
                    this.bAvailable = false
                    return true
                end

                return false
            end
        }
    })

    __Object:Attach()
    table.insert(arrHooks, __Object)
    ResumeThreads()
    return __Object
end

local function UnHooks()
    for _, pHookObject in pairs(arrHooks) do
        pHookObject:Remove()
    end

    arrHooks = {}
end

ffi.metatype("ShutDownWrapper", {
    __gc = function(self)
        UnHooks()
    end
})

local Wrapper = ffi.new("ShutDownWrapper")
events["present_queue"]:add(function() Wrapper.nRefCount = 0 end)
return {
    UnHooks = UnHooks,
    CreateVtable = CreateVtableHook,
    CreateInline = CreateInlineHook,
    GetHooks = function() return arrHooks end
}